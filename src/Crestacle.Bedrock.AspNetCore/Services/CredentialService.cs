using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Crestacle.Bedrock.Core.DomainEvents;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Services;

internal sealed partial class CredentialService : ICredentialService
{
    private readonly ICredentialRepository _credentialRepo;
    private readonly IEmailVerificationTokenRepository _emailTokenRepo;
    private readonly IEmailChangeTokenRepository _emailChangeTokenRepo;
    private readonly IPasswordResetTokenRepository _resetTokenRepo;
    private readonly IMagicLinkTokenRepository _magicLinkTokenRepo;
    private readonly IPasswordHistoryRepository _historyRepo;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IMfaChallengeRepository _mfaChallengeRepo;
    private readonly IOtpCodeRepository _otpCodeRepo;
    private readonly IRecoveryCodeRepository _recoveryCodeRepo;
    private readonly IAuditRepository _auditRepo;
    private readonly IBedrockUnitOfWork _unitOfWork;
    private readonly IPasswordHasher _hasher;
    private readonly IPasswordValidator _validator;
    private readonly ITokenService _tokenService;
    private readonly IMfaService _mfaService;
    private readonly IOtpService _otpService;
    private readonly IMfaPolicyService _mfaPolicy;
    private readonly IAnomalyDetector _anomalyDetector;
    private readonly IEmailSender _emailSender;
    private readonly ISmsSender _smsSender;
    private readonly IBedrockEventPublisher _eventPublisher;
    private readonly IBedrockCache _cache;
    private readonly OtpSendLimiter _otpSendLimiter;
    private readonly BedrockOptions _options;
    private readonly ILogger<CredentialService> _logger;

    public CredentialService(
        ICredentialRepository credentialRepo,
        IEmailVerificationTokenRepository emailTokenRepo,
        IEmailChangeTokenRepository emailChangeTokenRepo,
        IPasswordResetTokenRepository resetTokenRepo,
        IMagicLinkTokenRepository magicLinkTokenRepo,
        IPasswordHistoryRepository historyRepo,
        IRefreshTokenService refreshTokenService,
        IMfaChallengeRepository mfaChallengeRepo,
        IOtpCodeRepository otpCodeRepo,
        IRecoveryCodeRepository recoveryCodeRepo,
        IAuditRepository auditRepo,
        IBedrockUnitOfWork unitOfWork,
        IPasswordHasher hasher,
        IPasswordValidator validator,
        ITokenService tokenService,
        IMfaService mfaService,
        IOtpService otpService,
        IMfaPolicyService mfaPolicy,
        IAnomalyDetector anomalyDetector,
        IEmailSender emailSender,
        ISmsSender smsSender,
        IBedrockEventPublisher eventPublisher,
        IBedrockCache cache,
        OtpSendLimiter otpSendLimiter,
        IOptions<BedrockOptions> options,
        ILogger<CredentialService> logger)
    {
        _credentialRepo = credentialRepo;
        _emailTokenRepo = emailTokenRepo;
        _emailChangeTokenRepo = emailChangeTokenRepo;
        _resetTokenRepo = resetTokenRepo;
        _magicLinkTokenRepo = magicLinkTokenRepo;
        _historyRepo = historyRepo;
        _refreshTokenService = refreshTokenService;
        _mfaChallengeRepo = mfaChallengeRepo;
        _otpCodeRepo = otpCodeRepo;
        _recoveryCodeRepo = recoveryCodeRepo;
        _auditRepo = auditRepo;
        _unitOfWork = unitOfWork;
        _hasher = hasher;
        _validator = validator;
        _tokenService = tokenService;
        _mfaService = mfaService;
        _otpService = otpService;
        _mfaPolicy = mfaPolicy;
        _anomalyDetector = anomalyDetector;
        _emailSender = emailSender;
        _smsSender = smsSender;
        _eventPublisher = eventPublisher;
        _cache = cache;
        _otpSendLimiter = otpSendLimiter;
        _options = options.Value;
        _logger = logger;
    }

    // -------------------------------------------------------------------------
    // Registration & email
    // -------------------------------------------------------------------------

    public async Task RegisterAsync(Guid userId, string email, string password, string? tenantId = null, CancellationToken ct = default)
    {
        if (!_validator.IsValid(password, out var errors))
            throw new BedrockValidationException(errors);

        if (await _credentialRepo.ExistsByEmailAsync(email, ct))
            throw new BedrockValidationException("Email address is already registered.");

        var hash = _hasher.Hash(password);
        var credential = UserCredential.Create(userId, email, hash, tenantId);
        await _credentialRepo.AddAsync(credential, ct);

        await _historyRepo.AddAsync(PasswordHistory.Create(userId, hash, tenantId), ct);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);
        await _emailTokenRepo.AddAsync(
            EmailVerificationToken.Create(userId, tokenHash,
                DateTime.UtcNow.Add(_options.TokenExpiry.EmailVerificationToken), tenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);

        BedrockTelemetry.Registrations.Add(1);
        await _emailSender.SendEmailVerificationAsync(email, BuildVerificationUrl(rawToken), ct);
        await _eventPublisher.PublishAsync(new EmailVerificationRequestedEvent(userId, email, DateTime.UtcNow), ct);
    }

    public async Task ConfirmEmailAsync(string rawToken, CancellationToken ct = default)
    {
        var tokenHash = ComputeTokenHash(rawToken);
        var token = await _emailTokenRepo.GetByHashAsync(tokenHash, ct);

        if (token is null || !token.IsValid)
            throw new BedrockValidationException("The verification link is invalid or has expired.");

        var credential = await _credentialRepo.GetByUserIdAsync(token.UserId, ct)
            ?? throw new BedrockValidationException("The verification link is invalid or has expired.");

        token.MarkUsed();
        credential.ConfirmEmail();

        await _emailTokenRepo.UpdateAsync(token, ct);
        await _credentialRepo.UpdateAsync(credential, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.EmailVerified, "unknown", "unknown",
                credential.UserId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        LogEmailVerified(_logger, credential.UserId, credential.TenantId);
        await _eventPublisher.PublishAsync(new EmailVerifiedEvent(credential.UserId, DateTime.UtcNow), ct);
    }

    public async Task ResendConfirmationAsync(string email, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByEmailAsync(email, ct);

        if (credential is null || credential.EmailConfirmed)
            return;

        await _emailTokenRepo.InvalidateAllForUserAsync(credential.UserId, ct);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);
        await _emailTokenRepo.AddAsync(
            EmailVerificationToken.Create(credential.UserId, tokenHash,
                DateTime.UtcNow.Add(_options.TokenExpiry.EmailVerificationToken),
                credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        await _emailSender.SendEmailVerificationAsync(email, BuildVerificationUrl(rawToken), ct);
    }

    // -------------------------------------------------------------------------
    // Password management
    // -------------------------------------------------------------------------

    public async Task ChangePasswordAsync(Guid userId, string currentPassword, string newPassword, string byIp, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        if (!_hasher.Verify(currentPassword, credential.PasswordHash))
            throw new BedrockValidationException("Current password is incorrect.");

        if (!_validator.IsValid(newPassword, out var errors))
            throw new BedrockValidationException(errors);

        if (_options.Password.HistoryDepth > 0)
        {
            var history = await _historyRepo.GetRecentByUserAsync(userId, _options.Password.HistoryDepth, ct);
            if (_validator.IsPreviouslyUsed(newPassword, history.Select(h => h.PasswordHash)))
                throw new BedrockValidationException("Password has been used recently and cannot be reused.");
        }

        var newHash = _hasher.Hash(newPassword);
        credential.SetPassword(newHash);
        await _credentialRepo.UpdateAsync(credential, ct);

        await _historyRepo.AddAsync(PasswordHistory.Create(userId, newHash, credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        await _refreshTokenService.RevokeAllAsync(userId, byIp, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.PasswordChanged, byIp, "unknown",
                userId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        LogPasswordChanged(_logger, userId, credential.TenantId);

        if (_options.Password.HistoryDepth > 0)
            await _historyRepo.PruneAsync(userId, _options.Password.HistoryDepth, ct);

        await _eventPublisher.PublishAsync(new PasswordChangedEvent(userId, DateTime.UtcNow), ct);
    }

    public async Task RequestPasswordResetAsync(string email, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByEmailAsync(email, ct);

        if (credential is null)
            return;

        await _resetTokenRepo.InvalidateAllForUserAsync(credential.UserId, ct);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);
        await _resetTokenRepo.AddAsync(
            PasswordResetToken.Create(credential.UserId, tokenHash,
                DateTime.UtcNow.Add(_options.TokenExpiry.PasswordResetToken),
                credential.TenantId), ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.PasswordResetRequested, "unknown", "unknown",
                credential.UserId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        await _emailSender.SendPasswordResetAsync(email, BuildPasswordResetUrl(rawToken), ct);
        await _eventPublisher.PublishAsync(new PasswordResetRequestedEvent(credential.UserId, DateTime.UtcNow), ct);
    }

    public async Task ResetPasswordAsync(string rawToken, string newPassword, string byIp, CancellationToken ct = default)
    {
        var tokenHash = ComputeTokenHash(rawToken);
        var token = await _resetTokenRepo.GetByHashAsync(tokenHash, ct);

        if (token is null || !token.IsValid)
            throw new BedrockValidationException("The password reset link is invalid or has expired.");

        var credential = await _credentialRepo.GetByUserIdAsync(token.UserId, ct)
            ?? throw new BedrockValidationException("The password reset link is invalid or has expired.");

        if (!_validator.IsValid(newPassword, out var errors))
            throw new BedrockValidationException(errors);

        if (_options.Password.HistoryDepth > 0)
        {
            var history = await _historyRepo.GetRecentByUserAsync(token.UserId, _options.Password.HistoryDepth, ct);
            if (_validator.IsPreviouslyUsed(newPassword, history.Select(h => h.PasswordHash)))
                throw new BedrockValidationException("Password has been used recently and cannot be reused.");
        }

        token.MarkUsed();
        var newHash = _hasher.Hash(newPassword);
        credential.SetPassword(newHash);

        await _resetTokenRepo.UpdateAsync(token, ct);
        await _credentialRepo.UpdateAsync(credential, ct);
        await _historyRepo.AddAsync(PasswordHistory.Create(token.UserId, newHash, credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        await _refreshTokenService.RevokeAllAsync(token.UserId, byIp, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.PasswordReset, byIp, "unknown",
                token.UserId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        LogPasswordResetCompleted(_logger, token.UserId, credential.TenantId);

        if (_options.Password.HistoryDepth > 0)
            await _historyRepo.PruneAsync(token.UserId, _options.Password.HistoryDepth, ct);

        await _eventPublisher.PublishAsync(new PasswordResetCompletedEvent(token.UserId, DateTime.UtcNow), ct);
    }

    // -------------------------------------------------------------------------
    // Login — first factor
    // -------------------------------------------------------------------------

    public async Task<FirstFactorResult> LoginFirstFactorAsync(
        string email, string password, string ip, string userAgent, string fingerprintHash,
        CancellationToken ct = default)
    {
        using var activity = BedrockTelemetry.ActivitySource.StartActivity("bedrock.login");
        BedrockTelemetry.LoginAttempts.Add(1);

        if (_options.IpRateLimit.Enabled)
        {
            var raw = await _cache.GetAsync(
                $"Bedrock:ip-fail:{_anomalyDetector.ExtractIpBlock(ip)}", ct);
            if (raw is not null && int.Parse(raw) >= _options.IpRateLimit.MaxFailedAttemptsPerIp)
            {
                LogIpRateLimitExceeded(_logger, ip);
                throw new BedrockIpRateLimitException(_options.IpRateLimit.IpLockoutDuration);
            }
        }

        var credential = await _credentialRepo.GetByEmailAsync(email, ct);

        if (credential is null)
        {
            _ = _hasher.Hash(password); // constant-time: prevent email enumeration
            await IncrementIpFailCountAsync(ip, ct);
            await _auditRepo.AddAsync(AuditEntry.Create(AuditEventType.LoginFailed, ip, userAgent), ct);
            await _unitOfWork.SaveChangesAsync(ct);
            LogLoginFailedUnknownUser(_logger, ip);
            BedrockTelemetry.LoginFailures.Add(1);
            activity?.SetTag("bedrock.result", "failed");
            return FirstFactorResult.Failed();
        }

        activity?.SetTag("bedrock.user_id", credential.UserId.ToString());
        activity?.SetTag("bedrock.tenant_id", credential.TenantId);

        if (credential.IsLockedOut())
        {
            await IncrementIpFailCountAsync(ip, ct);
            await _auditRepo.AddAsync(
                AuditEntry.Create(AuditEventType.LoginFailed, ip, userAgent,
                    credential.UserId, tenantId: credential.TenantId), ct);
            await _unitOfWork.SaveChangesAsync(ct);
            LogLoginFailed(_logger, credential.UserId, credential.TenantId);
            BedrockTelemetry.LoginFailures.Add(1);
            activity?.SetTag("bedrock.result", "locked");
            return FirstFactorResult.Locked(credential.UserId, credential.LockoutEnd!.Value);
        }

        if (!_hasher.Verify(password, credential.PasswordHash))
        {
            await IncrementIpFailCountAsync(ip, ct);
            credential.RecordFailedLogin(_options.Lockout.MaxFailedAttempts, _options.Lockout.Duration);
            await _credentialRepo.UpdateAsync(credential, ct);

            var auditType = credential.IsLockedOut() ? AuditEventType.AccountLocked : AuditEventType.LoginFailed;
            await _auditRepo.AddAsync(
                AuditEntry.Create(auditType, ip, userAgent,
                    credential.UserId, tenantId: credential.TenantId), ct);
            await _unitOfWork.SaveChangesAsync(ct);

            LogLoginFailed(_logger, credential.UserId, credential.TenantId);
            if (credential.IsLockedOut())
            {
                LogAccountLocked(_logger, credential.UserId, credential.TenantId);
                BedrockTelemetry.AccountLockouts.Add(1);
                await _emailSender.SendAccountLockedAsync(email, credential.LockoutEnd!.Value, ct);
                BedrockTelemetry.LoginFailures.Add(1);
                activity?.SetTag("bedrock.result", "locked");
                return FirstFactorResult.Locked(credential.UserId, credential.LockoutEnd!.Value);
            }

            BedrockTelemetry.LoginFailures.Add(1);
            activity?.SetTag("bedrock.result", "failed");
            return FirstFactorResult.Failed();
        }

        // Password correct — stage all mutations; single save per code path below

        if (_hasher.NeedsRehash(credential.PasswordHash))
        {
            var rehashed = _hasher.Hash(password);
            credential.SetPassword(rehashed);
            await _historyRepo.AddAsync(PasswordHistory.Create(credential.UserId, rehashed, credential.TenantId), ct);
        }

        var wasLocked = credential.LockoutEnd.HasValue;
        credential.RecordSuccessfulLogin();
        await _credentialRepo.UpdateAsync(credential, ct);

        LogLoginSucceeded(_logger, credential.UserId, credential.TenantId);
        BedrockTelemetry.LoginSuccesses.Add(1);
        if (wasLocked)
            LogAccountUnlocked(_logger, credential.UserId, credential.TenantId);

        if (wasLocked)
            await _auditRepo.AddAsync(
                AuditEntry.Create(AuditEventType.AccountUnlocked, ip, userAgent,
                    credential.UserId, tenantId: credential.TenantId), ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.LoginSucceeded, ip, userAgent,
                credential.UserId, tenantId: credential.TenantId), ct);

        // Anomaly detection
        var ipBlock = _anomalyDetector.ExtractIpBlock(ip);
        var isAnomalous = _options.AnomalyDetection.Enabled
            && await _anomalyDetector.IsAnomalousAsync(credential.UserId, fingerprintHash, ipBlock, ct);

        if (isAnomalous)
        {
            await _auditRepo.AddAsync(
                AuditEntry.Create(AuditEventType.AnomalyDetected, ip, userAgent,
                    credential.UserId, tenantId: credential.TenantId), ct);
        }

        // MFA challenge: enrolled MFA OR anomaly-triggered (forces email OTP even without MFA)
        if ((credential.MfaEnabled && credential.MfaMethod.HasValue) || isAnomalous)
        {
            var method = (isAnomalous && !credential.MfaEnabled) || !credential.MfaMethod.HasValue
                ? MfaMethod.EmailOtp
                : credential.MfaMethod.Value;

            string? codeHash = null;

            if (method is MfaMethod.EmailOtp or MfaMethod.SmsOtp)
            {
                await _otpSendLimiter.GuardAsync(credential.UserId, OtpPurpose.Login, ct);
                await _otpCodeRepo.InvalidateAllForUserAsync(credential.UserId, OtpPurpose.Login, ct);
                var rawCode = _otpService.GenerateCode();
                codeHash = _otpService.HashCode(rawCode);
                await _otpCodeRepo.AddAsync(
                    OtpCode.Create(credential.UserId, OtpPurpose.Login, codeHash,
                        DateTime.UtcNow.Add(_options.TokenExpiry.OtpCode), credential.TenantId), ct);

                if (method == MfaMethod.EmailOtp)
                    await _emailSender.SendMfaOtpAsync(credential.Email, rawCode, ct);
                else
                    await _smsSender.SendOtpAsync(credential.Email, rawCode, ct);
            }

            var challengeExpiry = DateTime.UtcNow.Add(_options.TokenExpiry.MfaChallenge);
            var challenge = MfaChallenge.Create(
                credential.UserId, method, codeHash, ip, userAgent, challengeExpiry, credential.TenantId);
            await _mfaChallengeRepo.AddAsync(challenge, ct);

            // Single save: credential update + login audit + anomaly audit (if any) + OTP code + challenge
            await _unitOfWork.SaveChangesAsync(ct);

            if (wasLocked)
                await _eventPublisher.PublishAsync(new Crestacle.Bedrock.Core.Events.AccountUnlockedEvent(credential.UserId, DateTime.UtcNow), ct);
            await _eventPublisher.PublishAsync(
                new LoginSucceededEvent(credential.UserId, ip, credential.MfaEnabled, DateTime.UtcNow), ct);

            if (isAnomalous)
                await _eventPublisher.PublishAsync(
                    new AnomalyDetectedEvent(credential.UserId, ip, fingerprintHash, DateTime.UtcNow), ct);

            var challengeToken = _tokenService.GenerateChallengeToken(challenge.Id, credential.UserId);
            BedrockTelemetry.MfaChallengesIssued.Add(1);
            activity?.SetTag("bedrock.mfa_required", true);
            activity?.SetTag("bedrock.result", "mfa_required");
            return FirstFactorResult.MfaRequired(credential.UserId,
                new MfaChallengeResult(challengeToken, method, challengeExpiry));
        }

        // Mandatory MFA policy check (delegated to MfaPolicyService)
        if (_mfaPolicy.IsMfaRequired(credential))
        {
            if (_mfaPolicy.GracePeriodExpired(credential))
            {
                await _unitOfWork.SaveChangesAsync(ct);
                if (wasLocked)
                    await _eventPublisher.PublishAsync(new Crestacle.Bedrock.Core.Events.AccountUnlockedEvent(credential.UserId, DateTime.UtcNow), ct);
                await _eventPublisher.PublishAsync(
                    new LoginSucceededEvent(credential.UserId, ip, false, DateTime.UtcNow), ct);
                var enrollmentToken = _tokenService.GenerateEnrollmentToken(credential.UserId);
                activity?.SetTag("bedrock.mfa_required", false);
                activity?.SetTag("bedrock.result", "success");
                return FirstFactorResult.EnrollmentRequired(credential.UserId, enrollmentToken);
            }

            if (!credential.MfaGracePeriodEndsAt.HasValue)
            {
                // First encounter: set grace period, record device, single save
                var gracePeriodEnd = _mfaPolicy.SetGracePeriod(credential);
                await _credentialRepo.UpdateAsync(credential, ct);
                await _anomalyDetector.RecordDeviceAsync(credential.UserId, fingerprintHash, ipBlock, userAgent, ct);
                await _unitOfWork.SaveChangesAsync(ct);
                if (wasLocked)
                    await _eventPublisher.PublishAsync(new Crestacle.Bedrock.Core.Events.AccountUnlockedEvent(credential.UserId, DateTime.UtcNow), ct);
                await _eventPublisher.PublishAsync(
                    new LoginSucceededEvent(credential.UserId, ip, false, DateTime.UtcNow), ct);
                activity?.SetTag("bedrock.mfa_required", false);
                activity?.SetTag("bedrock.result", "success");
                return FirstFactorResult.SuccessInGracePeriod(credential.UserId, gracePeriodEnd);
            }

            // Already in grace period: record device, single save
            await _anomalyDetector.RecordDeviceAsync(credential.UserId, fingerprintHash, ipBlock, userAgent, ct);
            await _unitOfWork.SaveChangesAsync(ct);
            if (wasLocked)
                await _eventPublisher.PublishAsync(new Crestacle.Bedrock.Core.Events.AccountUnlockedEvent(credential.UserId, DateTime.UtcNow), ct);
            await _eventPublisher.PublishAsync(
                new LoginSucceededEvent(credential.UserId, ip, false, DateTime.UtcNow), ct);
            activity?.SetTag("bedrock.mfa_required", false);
            activity?.SetTag("bedrock.result", "success");
            return FirstFactorResult.SuccessInGracePeriod(
                credential.UserId, credential.MfaGracePeriodEndsAt!.Value);
        }

        // Full success — record device, single save
        await _anomalyDetector.RecordDeviceAsync(credential.UserId, fingerprintHash, ipBlock, userAgent, ct);
        await _unitOfWork.SaveChangesAsync(ct);

        if (wasLocked)
            await _eventPublisher.PublishAsync(new Crestacle.Bedrock.Core.Events.AccountUnlockedEvent(credential.UserId, DateTime.UtcNow), ct);
        await _eventPublisher.PublishAsync(
            new LoginSucceededEvent(credential.UserId, ip, credential.MfaEnabled, DateTime.UtcNow), ct);

        activity?.SetTag("bedrock.mfa_required", false);
        activity?.SetTag("bedrock.result", "success");
        return FirstFactorResult.Success(credential.UserId, credential.MfaEnabled);
    }

    // -------------------------------------------------------------------------
    // Login — MFA verification
    // -------------------------------------------------------------------------

    public async Task<Guid> VerifyMfaAsync(
        string challengeToken, string code, string ip, string userAgent,
        CancellationToken ct = default)
    {
        var challengeId = _tokenService.ValidateChallengeToken(challengeToken)
            ?? throw new BedrockValidationException("Invalid or expired challenge token.");

        var challenge = await _mfaChallengeRepo.GetByIdAsync(challengeId, ct)
            ?? throw new BedrockValidationException("Invalid or expired challenge token.");

        if (!challenge.IsValid)
            throw new BedrockValidationException("The MFA challenge has expired or already been used.");

        var credential = await _credentialRepo.GetByUserIdAsync(challenge.UserId, ct)
            ?? throw new BedrockValidationException("User not found.");

        if (credential.IsLockedOut())
            throw new BedrockAccountLockedException(credential.LockoutEnd!.Value);

        var verified = false;

        switch (challenge.Method)
        {
            case MfaMethod.Totp when credential.TotpSecretEncrypted is not null:
                verified = await _mfaService.VerifyTotp(credential.TotpSecretEncrypted, code, challenge.UserId, ct);
                break;

            case MfaMethod.EmailOtp:
            case MfaMethod.SmsOtp:
                if (challenge.CodeHash is not null)
                    verified = _otpService.VerifyCode(code, challenge.CodeHash);
                break;
        }

        // Recovery code fallback
        if (!verified)
        {
            var inputHash = ComputeTokenHash(code);
            var recoveryCode = await _recoveryCodeRepo.GetByHashAsync(challenge.UserId, inputHash, ct);
            if (recoveryCode?.IsAvailable == true && _mfaService.VerifyRecoveryCode(code, recoveryCode.CodeHash))
            {
                verified = true;
                recoveryCode.MarkUsed();
                await _recoveryCodeRepo.UpdateAsync(recoveryCode, ct);
                await _auditRepo.AddAsync(
                    AuditEntry.Create(AuditEventType.RecoveryCodeUsed, ip, userAgent,
                        challenge.UserId, tenantId: credential.TenantId), ct);
            }
        }

        if (!verified)
        {
            credential.RecordFailedLogin(_options.Lockout.MaxFailedAttempts, _options.Lockout.Duration);
            await _credentialRepo.UpdateAsync(credential, ct);
            await _auditRepo.AddAsync(
                AuditEntry.Create(AuditEventType.MfaChallengeFailed, ip, userAgent,
                    challenge.UserId, tenantId: credential.TenantId), ct);
            await _unitOfWork.SaveChangesAsync(ct);

            if (credential.IsLockedOut())
                throw new BedrockAccountLockedException(credential.LockoutEnd!.Value);

            throw new BedrockValidationException("The verification code is incorrect.");
        }

        challenge.MarkUsed();
        await _mfaChallengeRepo.UpdateAsync(challenge, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.MfaChallengeSucceeded, ip, userAgent,
                challenge.UserId, tenantId: credential.TenantId), ct);

        // Record device on successful MFA completion — staged alongside challenge + audit
        var fingerprint = _anomalyDetector.ComputeFingerprint(userAgent, ip);
        var ipBlock = _anomalyDetector.ExtractIpBlock(ip);
        await _anomalyDetector.RecordDeviceAsync(challenge.UserId, fingerprint, ipBlock, userAgent, ct);

        await _unitOfWork.SaveChangesAsync(ct);

        await _eventPublisher.PublishAsync(
            new MfaChallengeSucceededEvent(challenge.UserId, ip, DateTime.UtcNow), ct);

        return challenge.UserId;
    }

    // -------------------------------------------------------------------------
    // MFA enrollment
    // -------------------------------------------------------------------------

    public async Task<TotpSetupResult> SetupTotpAsync(Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        var issuer = string.IsNullOrEmpty(_options.Mfa.Issuer) ? "Bedrock" : _options.Mfa.Issuer;
        var (plainSecret, qrUri) = _mfaService.GenerateTotpSetup(credential.Email, issuer);
        var encryptedSecret = _mfaService.EncryptSecret(plainSecret);

        credential.SetTotpSecret(encryptedSecret);
        await _credentialRepo.UpdateAsync(credential, ct);
        await _unitOfWork.SaveChangesAsync(ct);

        return new TotpSetupResult(qrUri);
    }

    public async Task<RecoveryCodesResult> ConfirmTotpAsync(Guid userId, string code, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        if (credential.TotpSecretEncrypted is null)
            throw new BedrockValidationException("TOTP setup has not been initiated.");

        if (!await _mfaService.VerifyTotp(credential.TotpSecretEncrypted, code, ct: ct))
            throw new BedrockValidationException("The TOTP code is incorrect.");

        credential.ConfirmTotp();
        credential.EnableMfa(MfaMethod.Totp);
        await _credentialRepo.UpdateAsync(credential, ct);

        var plainCodes = _mfaService.GenerateRecoveryCodes(_options.Mfa.BackupCodeCount);
        await _recoveryCodeRepo.InvalidateAllForUserAsync(userId, ct);
        var codeEntities = plainCodes.Select(c =>
            RecoveryCode.Create(userId, ComputeTokenHash(c), credential.TenantId)).ToList();
        await _recoveryCodeRepo.AddRangeAsync(codeEntities, ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.MfaEnabled, "unknown", "unknown",
                userId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        await _eventPublisher.PublishAsync(new MfaEnabledEvent(userId, MfaMethod.Totp, DateTime.UtcNow), ct);

        return new RecoveryCodesResult(plainCodes);
    }

    public async Task<RecoveryCodesResult> SetupOtpAsync(Guid userId, MfaMethod method, CancellationToken ct = default)
    {
        if (method is not (MfaMethod.EmailOtp or MfaMethod.SmsOtp))
            throw new BedrockValidationException("Method must be EmailOtp or SmsOtp.");

        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        credential.EnableMfa(method);
        await _credentialRepo.UpdateAsync(credential, ct);

        var plainCodes = _mfaService.GenerateRecoveryCodes(_options.Mfa.BackupCodeCount);
        await _recoveryCodeRepo.InvalidateAllForUserAsync(userId, ct);
        var codeEntities = plainCodes.Select(c =>
            RecoveryCode.Create(userId, ComputeTokenHash(c), credential.TenantId)).ToList();
        await _recoveryCodeRepo.AddRangeAsync(codeEntities, ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.MfaEnabled, "unknown", "unknown",
                userId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        await _eventPublisher.PublishAsync(new MfaEnabledEvent(userId, method, DateTime.UtcNow), ct);

        return new RecoveryCodesResult(plainCodes);
    }

    public async Task<RecoveryCodesResult> RegenerateRecoveryCodesAsync(Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        if (!credential.MfaEnabled)
            throw new BedrockValidationException("MFA is not enabled for this user.");

        var plainCodes = _mfaService.GenerateRecoveryCodes(_options.Mfa.BackupCodeCount);
        await _recoveryCodeRepo.InvalidateAllForUserAsync(userId, ct);
        var codeEntities = plainCodes.Select(c =>
            RecoveryCode.Create(userId, ComputeTokenHash(c), credential.TenantId)).ToList();
        await _recoveryCodeRepo.AddRangeAsync(codeEntities, ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.RecoveryCodesRegenerated, "unknown", "unknown",
                userId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        return new RecoveryCodesResult(plainCodes);
    }

    public async Task DisableMfaAsync(Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        credential.DisableMfa();
        await _credentialRepo.UpdateAsync(credential, ct);

        await _recoveryCodeRepo.InvalidateAllForUserAsync(userId, ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.MfaDisabled, "unknown", "unknown",
                userId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        await _eventPublisher.PublishAsync(new MfaDisabledEvent(userId, DateTime.UtcNow), ct);
    }

    public Task<int> GetRemainingRecoveryCodeCountAsync(Guid userId, CancellationToken ct = default)
        => _recoveryCodeRepo.CountAvailableAsync(userId, ct);

    // -------------------------------------------------------------------------
    // Email change
    // -------------------------------------------------------------------------

    public async Task RequestEmailChangeAsync(
        Guid userId, string newEmail, string ipAddress, string userAgent, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        if (await _credentialRepo.ExistsByEmailAsync(newEmail, ct))
            throw new BedrockValidationException("This email address is already in use.");

        await _emailChangeTokenRepo.InvalidateAllForUserAsync(userId, ct);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);
        await _emailChangeTokenRepo.AddAsync(
            EmailChangeToken.Create(userId, tokenHash, newEmail,
                DateTime.UtcNow.Add(_options.TokenExpiry.EmailChangeToken),
                credential.TenantId), ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.EmailChangeRequested, ipAddress, userAgent,
                userId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);

        await _emailSender.SendEmailChangeVerificationAsync(newEmail, BuildEmailChangeUrl(rawToken), ct);
        await _emailSender.SendEmailChangeNotificationAsync(credential.Email, ct);
    }

    public async Task ConfirmEmailChangeAsync(string rawToken, CancellationToken ct = default)
    {
        var tokenHash = ComputeTokenHash(rawToken);
        var token = await _emailChangeTokenRepo.GetByHashAsync(tokenHash, ct);

        if (token is null || !token.IsValid)
            throw new BedrockValidationException("The email change link is invalid or has expired.");

        var credential = await _credentialRepo.GetByUserIdAsync(token.UserId, ct)
            ?? throw new BedrockValidationException("The email change link is invalid or has expired.");

        // Guard: another user may have registered the target address while the token was pending
        if (await _credentialRepo.ExistsByEmailAsync(token.NewEmail, ct))
            throw new BedrockValidationException("This email address is already in use.");

        token.MarkUsed();
        credential.ChangeEmail(token.NewEmail);

        await _emailChangeTokenRepo.UpdateAsync(token, ct);
        await _credentialRepo.UpdateAsync(credential, ct);
        await _unitOfWork.SaveChangesAsync(ct);

        await _refreshTokenService.RevokeAllAsync(credential.UserId, "email-change", ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.EmailChanged, "unknown", "unknown",
                credential.UserId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        LogEmailChanged(_logger, credential.UserId, credential.TenantId);
    }

    // -------------------------------------------------------------------------
    // Magic link (passwordless login)
    // -------------------------------------------------------------------------

    public async Task RequestMagicLinkAsync(
        string email, string ipAddress, string userAgent, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByEmailAsync(email, ct);

        if (credential is null || !credential.EmailConfirmed || credential.IsLockedOut())
            return;

        await _magicLinkTokenRepo.InvalidateAllForUserAsync(credential.UserId, ct);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);
        await _magicLinkTokenRepo.AddAsync(
            MagicLinkToken.Create(credential.UserId, tokenHash,
                DateTime.UtcNow.Add(_options.TokenExpiry.MagicLinkToken),
                ipAddress, credential.TenantId), ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.MagicLinkRequested, ipAddress, userAgent,
                credential.UserId, tenantId: credential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);

        await _emailSender.SendMagicLinkAsync(email, BuildMagicLinkUrl(rawToken), ct);
        LogMagicLinkRequested(_logger, credential.UserId, credential.TenantId);
    }

    public async Task<FirstFactorResult> VerifyMagicLinkAsync(
        string rawToken, string ipAddress, string userAgent, CancellationToken ct = default)
    {
        var tokenHash = ComputeTokenHash(rawToken);
        var token = await _magicLinkTokenRepo.GetByHashAsync(tokenHash, ct);

        if (token is null || !token.IsValid)
            return FirstFactorResult.Failed();

        var credential = await _credentialRepo.GetByUserIdAsync(token.UserId, ct);

        if (credential is null)
            return FirstFactorResult.Failed();

        if (credential.IsLockedOut())
            return FirstFactorResult.Locked(credential.UserId, credential.LockoutEnd!.Value);

        token.MarkUsed();
        await _magicLinkTokenRepo.UpdateAsync(token, ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.MagicLinkConsumed, ipAddress, userAgent,
                credential.UserId, tenantId: credential.TenantId), ct);

        // Enrolled MFA challenge
        if (credential.MfaEnabled && credential.MfaMethod.HasValue)
        {
            string? codeHash = null;
            var method = credential.MfaMethod!.Value;

            if (method is MfaMethod.EmailOtp or MfaMethod.SmsOtp)
            {
                await _otpSendLimiter.GuardAsync(credential.UserId, OtpPurpose.Login, ct);
                await _otpCodeRepo.InvalidateAllForUserAsync(credential.UserId, OtpPurpose.Login, ct);
                var rawCode = _otpService.GenerateCode();
                codeHash = _otpService.HashCode(rawCode);
                await _otpCodeRepo.AddAsync(
                    OtpCode.Create(credential.UserId, OtpPurpose.Login, codeHash,
                        DateTime.UtcNow.Add(_options.TokenExpiry.OtpCode), credential.TenantId), ct);

                if (method == MfaMethod.EmailOtp)
                    await _emailSender.SendMfaOtpAsync(credential.Email, rawCode, ct);
                else
                    await _smsSender.SendOtpAsync(credential.Email, rawCode, ct);
            }

            var challengeExpiry = DateTime.UtcNow.Add(_options.TokenExpiry.MfaChallenge);
            var challenge = MfaChallenge.Create(
                credential.UserId, method, codeHash, ipAddress, userAgent, challengeExpiry, credential.TenantId);
            await _mfaChallengeRepo.AddAsync(challenge, ct);

            await _unitOfWork.SaveChangesAsync(ct);
            LogMagicLinkConsumed(_logger, credential.UserId, credential.TenantId);

            var challengeToken = _tokenService.GenerateChallengeToken(challenge.Id, credential.UserId);
            return FirstFactorResult.MfaRequired(credential.UserId,
                new MfaChallengeResult(challengeToken, method, challengeExpiry));
        }

        // Mandatory MFA policy check
        if (_mfaPolicy.IsMfaRequired(credential))
        {
            if (_mfaPolicy.GracePeriodExpired(credential))
            {
                await _unitOfWork.SaveChangesAsync(ct);
                LogMagicLinkConsumed(_logger, credential.UserId, credential.TenantId);
                var enrollmentToken = _tokenService.GenerateEnrollmentToken(credential.UserId);
                return FirstFactorResult.EnrollmentRequired(credential.UserId, enrollmentToken);
            }

            var fingerprint = _anomalyDetector.ComputeFingerprint(userAgent, ipAddress);
            var ipBlock = _anomalyDetector.ExtractIpBlock(ipAddress);

            if (!credential.MfaGracePeriodEndsAt.HasValue)
            {
                var gracePeriodEnd = _mfaPolicy.SetGracePeriod(credential);
                await _credentialRepo.UpdateAsync(credential, ct);
                await _anomalyDetector.RecordDeviceAsync(credential.UserId, fingerprint, ipBlock, userAgent, ct);
                await _unitOfWork.SaveChangesAsync(ct);
                LogMagicLinkConsumed(_logger, credential.UserId, credential.TenantId);
                return FirstFactorResult.SuccessInGracePeriod(credential.UserId, gracePeriodEnd);
            }

            await _anomalyDetector.RecordDeviceAsync(credential.UserId, fingerprint, ipBlock, userAgent, ct);
            await _unitOfWork.SaveChangesAsync(ct);
            LogMagicLinkConsumed(_logger, credential.UserId, credential.TenantId);
            return FirstFactorResult.SuccessInGracePeriod(credential.UserId, credential.MfaGracePeriodEndsAt!.Value);
        }

        await _unitOfWork.SaveChangesAsync(ct);
        LogMagicLinkConsumed(_logger, credential.UserId, credential.TenantId);
        return FirstFactorResult.Success(credential.UserId, credential.MfaEnabled);
    }

    // -------------------------------------------------------------------------
    // Account erasure
    // -------------------------------------------------------------------------

    public async Task AnonymizeAsync(Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        var tenantId = credential.TenantId;
        credential.Anonymize();
        await _credentialRepo.UpdateAsync(credential, ct);
        await _unitOfWork.SaveChangesAsync(ct);

        await _refreshTokenService.RevokeAllAsync(userId, "system", ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AccountAnonymized, "system", "unknown",
                userId, tenantId: tenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        LogAccountAnonymized(_logger, userId, tenantId);
    }

    // -------------------------------------------------------------------------
    // Logging
    // -------------------------------------------------------------------------

    [LoggerMessage(1001, LogLevel.Information, "Login succeeded: userId={UserId} tenant={TenantId}")]
    private static partial void LogLoginSucceeded(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1002, LogLevel.Warning, "Login failed (unknown user): ip={Ip}")]
    private static partial void LogLoginFailedUnknownUser(ILogger logger, string ip);

    [LoggerMessage(1003, LogLevel.Warning, "Login failed: userId={UserId} tenant={TenantId}")]
    private static partial void LogLoginFailed(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1004, LogLevel.Warning, "Account locked: userId={UserId} tenant={TenantId}")]
    private static partial void LogAccountLocked(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1005, LogLevel.Information, "Account unlocked: userId={UserId} tenant={TenantId}")]
    private static partial void LogAccountUnlocked(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1006, LogLevel.Information, "Password changed: userId={UserId} tenant={TenantId}")]
    private static partial void LogPasswordChanged(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1007, LogLevel.Information, "Email verified: userId={UserId} tenant={TenantId}")]
    private static partial void LogEmailVerified(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1008, LogLevel.Information, "Password reset completed: userId={UserId} tenant={TenantId}")]
    private static partial void LogPasswordResetCompleted(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1009, LogLevel.Information, "Account anonymized: userId={UserId} tenant={TenantId}")]
    private static partial void LogAccountAnonymized(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1010, LogLevel.Information, "Email changed: userId={UserId} tenant={TenantId}")]
    private static partial void LogEmailChanged(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1011, LogLevel.Information, "Magic link requested: userId={UserId} tenant={TenantId}")]
    private static partial void LogMagicLinkRequested(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1012, LogLevel.Information, "Magic link consumed: userId={UserId} tenant={TenantId}")]
    private static partial void LogMagicLinkConsumed(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(1013, LogLevel.Warning, "IP rate limit exceeded: ip={Ip}")]
    private static partial void LogIpRateLimitExceeded(ILogger logger, string ip);

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private async Task IncrementIpFailCountAsync(string ip, CancellationToken ct)
    {
        if (!_options.IpRateLimit.Enabled)
            return;
        var ipBlock = _anomalyDetector.ExtractIpBlock(ip);
        var key = $"Bedrock:ip-fail:{ipBlock}";
        var raw = await _cache.GetAsync(key, ct);
        var count = raw is null ? 0 : int.Parse(raw);
        await _cache.SetAsync(key, (count + 1).ToString(), _options.IpRateLimit.IpLockoutWindow, ct);
    }

    private static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string ComputeTokenHash(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private string BuildVerificationUrl(string rawToken)
    {
        var baseUrl = _options.Email.FrontendBaseUrl.TrimEnd('/');
        return $"{baseUrl}{_options.Email.EmailVerificationPath}?token={Uri.EscapeDataString(rawToken)}";
    }

    private string BuildPasswordResetUrl(string rawToken)
    {
        var baseUrl = _options.Email.FrontendBaseUrl.TrimEnd('/');
        return $"{baseUrl}{_options.Email.PasswordResetPath}?token={Uri.EscapeDataString(rawToken)}";
    }

    private string BuildEmailChangeUrl(string rawToken)
    {
        var baseUrl = _options.Email.FrontendBaseUrl.TrimEnd('/');
        return $"{baseUrl}{_options.Email.EmailChangePath}?token={Uri.EscapeDataString(rawToken)}";
    }

    private string BuildMagicLinkUrl(string rawToken)
    {
        var baseUrl = _options.Email.FrontendBaseUrl.TrimEnd('/');
        return $"{baseUrl}{_options.Email.MagicLinkPath}?token={Uri.EscapeDataString(rawToken)}";
    }
}
