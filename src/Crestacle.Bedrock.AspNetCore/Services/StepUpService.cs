using Crestacle.Bedrock.Core.DomainEvents;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Services;

internal sealed class StepUpService : IStepUpService
{
    private readonly ICredentialRepository _credentialRepo;
    private readonly IStepUpChallengeRepository _challengeRepo;
    private readonly IOtpCodeRepository _otpCodeRepo;
    private readonly IAuditRepository _auditRepo;
    private readonly IBedrockUnitOfWork _unitOfWork;
    private readonly ITokenService _tokenService;
    private readonly IMfaService _mfaService;
    private readonly IOtpService _otpService;
    private readonly IEmailSender _emailSender;
    private readonly ISmsSender _smsSender;
    private readonly IBedrockEventPublisher _eventPublisher;
    private readonly OtpSendLimiter _otpSendLimiter;
    private readonly StepUpAttemptLimiter _stepUpAttemptLimiter;
    private readonly BedrockOptions _options;

    public StepUpService(
        ICredentialRepository credentialRepo,
        IStepUpChallengeRepository challengeRepo,
        IOtpCodeRepository otpCodeRepo,
        IAuditRepository auditRepo,
        IBedrockUnitOfWork unitOfWork,
        ITokenService tokenService,
        IMfaService mfaService,
        IOtpService otpService,
        IEmailSender emailSender,
        ISmsSender smsSender,
        IBedrockEventPublisher eventPublisher,
        OtpSendLimiter otpSendLimiter,
        StepUpAttemptLimiter stepUpAttemptLimiter,
        IOptions<BedrockOptions> options)
    {
        _credentialRepo = credentialRepo;
        _challengeRepo = challengeRepo;
        _otpCodeRepo = otpCodeRepo;
        _auditRepo = auditRepo;
        _unitOfWork = unitOfWork;
        _tokenService = tokenService;
        _mfaService = mfaService;
        _otpService = otpService;
        _emailSender = emailSender;
        _smsSender = smsSender;
        _eventPublisher = eventPublisher;
        _otpSendLimiter = otpSendLimiter;
        _stepUpAttemptLimiter = stepUpAttemptLimiter;
        _options = options.Value;
    }

    public async Task<StepUpChallengeResult> InitiateAsync(
        Guid userId,
        string ip,
        string userAgent,
        CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        if (!credential.MfaEnabled || !credential.MfaMethod.HasValue)
            throw new BedrockValidationException("Step-up requires MFA to be enabled.");

        var method = credential.MfaMethod.Value;
        string? codeHash = null;

        if (method is MfaMethod.EmailOtp or MfaMethod.SmsOtp)
        {
            await _otpSendLimiter.GuardAsync(userId, OtpPurpose.StepUp, ct);
            await _otpCodeRepo.InvalidateAllForUserAsync(userId, OtpPurpose.StepUp, ct);
            var rawCode = _otpService.GenerateCode();
            codeHash = _otpService.HashCode(rawCode);
            await _otpCodeRepo.AddAsync(
                OtpCode.Create(userId, OtpPurpose.StepUp, codeHash,
                    DateTime.UtcNow.Add(_options.TokenExpiry.OtpCode), credential.TenantId), ct);

            if (method == MfaMethod.EmailOtp)
                await _emailSender.SendMfaOtpAsync(credential.Email, rawCode, ct);
            else
                await _smsSender.SendOtpAsync(credential.Email, rawCode, ct);
        }

        var expiresAt = DateTime.UtcNow.Add(_options.TokenExpiry.StepUpToken);
        var challenge = StepUpChallenge.Create(userId, method, codeHash, ip, expiresAt, credential.TenantId);
        await _challengeRepo.AddAsync(challenge, ct);
        await _unitOfWork.SaveChangesAsync(ct);

        return new StepUpChallengeResult(challenge.Id, method);
    }

    public async Task<string> VerifyAsync(
        Guid userId,
        Guid challengeId,
        string code,
        string ip,
        string userAgent,
        CancellationToken ct = default)
    {
        var challenge = await _challengeRepo.GetByIdAsync(challengeId, ct)
            ?? throw new BedrockValidationException("Step-up challenge not found or expired.");

        if (challenge.UserId != userId)
            throw new BedrockValidationException("Step-up challenge does not belong to this user.");

        if (!challenge.IsValid)
            throw new BedrockValidationException("The step-up challenge has expired or already been used.");

        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockValidationException("User not found.");

        var verified = false;

        switch (challenge.Method)
        {
            case MfaMethod.Totp when credential.TotpSecretEncrypted is not null:
                verified = await _mfaService.VerifyTotp(credential.TotpSecretEncrypted, code, userId, ct);
                break;

            case MfaMethod.EmailOtp:
            case MfaMethod.SmsOtp:
                var otpCode = await _otpCodeRepo.GetActiveByUserAndPurposeAsync(userId, OtpPurpose.StepUp, ct);
                if (otpCode is not null && _otpService.VerifyCode(code, otpCode.CodeHash))
                {
                    verified = true;
                    otpCode.MarkUsed();
                    await _otpCodeRepo.UpdateAsync(otpCode, ct);
                }
                break;
        }

        if (!verified)
        {
            await _auditRepo.AddAsync(
                AuditEntry.Create(AuditEventType.StepUpFailed, ip, userAgent,
                    userId, tenantId: credential.TenantId), ct);

            // Throttle guessing against this specific challenge. Once the max-attempts
            // threshold is exceeded, invalidate the challenge outright (rather than merely
            // continuing to reject) so the attacker can't keep guessing until it naturally
            // expires. The RowVersion/xmin concurrency token on StepUpChallenge (added for the
            // TOCTOU fix) makes this save safe even if a concurrent request is also failing.
            var limitExceeded = await _stepUpAttemptLimiter.RecordFailureAndCheckAsync(challengeId, ct);
            if (limitExceeded)
            {
                challenge.MarkUsed();
                await _challengeRepo.UpdateAsync(challenge, ct);
            }

            await _unitOfWork.SaveChangesAsync(ct);
            await _eventPublisher.PublishAsync(new StepUpFailedEvent(userId, ip, DateTime.UtcNow), ct);

            if (limitExceeded)
                throw new BedrockRateLimitException(_options.TokenExpiry.StepUpToken);

            throw new BedrockValidationException("The step-up code is incorrect.");
        }

        // MarkUsed is deferred to [RequiresStepUp] filter on first protected endpoint use.
        // Save audit only here; challenge.UsedAt stays null until first use of the JWT.
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.StepUpCompleted, ip, userAgent,
                userId, tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        await _eventPublisher.PublishAsync(new StepUpCompletedEvent(userId, ip, DateTime.UtcNow), ct);

        return _tokenService.GenerateStepUpToken(challenge.Id, userId);
    }
}
