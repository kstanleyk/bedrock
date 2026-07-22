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

internal sealed partial class BedrockAdminService : IBedrockAdminService
{
    private readonly ICredentialRepository _credentialRepo;
    private readonly IRecoveryCodeRepository _recoveryCodeRepo;
    private readonly IPasswordHistoryRepository _historyRepo;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IAuditRepository _auditRepo;
    private readonly IBedrockUnitOfWork _unitOfWork;
    private readonly IPasswordHasher _hasher;
    private readonly IPasswordValidator _validator;
    private readonly BedrockOptions _options;
    private readonly ILogger<BedrockAdminService> _logger;

    public BedrockAdminService(
        ICredentialRepository credentialRepo,
        IRecoveryCodeRepository recoveryCodeRepo,
        IPasswordHistoryRepository historyRepo,
        IRefreshTokenService refreshTokenService,
        IAuditRepository auditRepo,
        IBedrockUnitOfWork unitOfWork,
        IPasswordHasher hasher,
        IPasswordValidator validator,
        IOptions<BedrockOptions> options,
        ILogger<BedrockAdminService> logger)
    {
        _credentialRepo = credentialRepo;
        _recoveryCodeRepo = recoveryCodeRepo;
        _historyRepo = historyRepo;
        _refreshTokenService = refreshTokenService;
        _auditRepo = auditRepo;
        _unitOfWork = unitOfWork;
        _hasher = hasher;
        _validator = validator;
        _options = options.Value;
        _logger = logger;
    }

    public Task<PagedResult<CredentialSummary>> GetUsersAsync(
        int page, int pageSize, CancellationToken ct = default)
        => _credentialRepo.GetPagedAsync(page, pageSize, ct);

    public async Task<CredentialDetail> GetUserAsync(Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");
        return ToDetail(credential);
    }

    public async Task LockUserAsync(Guid adminId, Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");

        credential.AdminLock();
        await _credentialRepo.UpdateAsync(credential, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AdminAccountLocked, "admin", "admin",
                userId, metadata: adminId.ToString(), tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        LogAdminLocked(_logger, adminId, userId);
    }

    public async Task UnlockUserAsync(Guid adminId, Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");

        credential.AdminUnlock();
        await _credentialRepo.UpdateAsync(credential, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AdminAccountUnlocked, "admin", "admin",
                userId, metadata: adminId.ToString(), tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        LogAdminUnlocked(_logger, adminId, userId);
    }

    public async Task ResetMfaAsync(Guid adminId, Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");

        credential.DisableMfa();
        await _credentialRepo.UpdateAsync(credential, ct);
        await _recoveryCodeRepo.InvalidateAllForUserAsync(userId, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AdminMfaReset, "admin", "admin",
                userId, metadata: adminId.ToString(), tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        LogAdminMfaReset(_logger, adminId, userId);
    }

    public async Task ExpirePasswordAsync(Guid adminId, Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");

        credential.ExpirePassword();
        await _credentialRepo.UpdateAsync(credential, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AdminPasswordExpired, "admin", "admin",
                userId, metadata: adminId.ToString(), tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        LogAdminPasswordExpired(_logger, adminId, userId);
    }

    public async Task RevokeAllSessionsAsync(Guid adminId, Guid userId, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");

        await _refreshTokenService.RevokeAllAsync(userId, "admin", ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AdminSessionsRevoked, "admin", "admin",
                userId, metadata: adminId.ToString(), tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        LogAdminSessionsRevoked(_logger, adminId, userId);
    }

    public async Task ResetPasswordAsync(Guid adminId, Guid userId, string newPassword, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");

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
        // An admin reset is the common recovery path for a lockout, so clear it here too - otherwise
        // the user has a correct new password but is still locked out until it separately expires.
        credential.AdminUnlock();
        await _credentialRepo.UpdateAsync(credential, ct);

        await _historyRepo.AddAsync(PasswordHistory.Create(userId, newHash, credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        await _refreshTokenService.RevokeAllAsync(userId, "admin", ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AdminPasswordReset, "admin", "admin",
                userId, metadata: adminId.ToString(), tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);

        if (_options.Password.HistoryDepth > 0)
            await _historyRepo.PruneAsync(userId, _options.Password.HistoryDepth, ct);

        LogAdminPasswordReset(_logger, adminId, userId);
    }

    public async Task AdminChangeEmailAsync(Guid adminId, Guid userId, string newEmail, CancellationToken ct = default)
    {
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct)
            ?? throw new BedrockNotFoundException($"User {userId} not found.");

        if (string.Equals(credential.Email, newEmail, StringComparison.OrdinalIgnoreCase))
            return;

        if (await _credentialRepo.ExistsByEmailAsync(newEmail, ct))
            throw new BedrockValidationException("This email address is already in use.");

        credential.ChangeEmail(newEmail);
        await _credentialRepo.UpdateAsync(credential, ct);
        await _unitOfWork.SaveChangesAsync(ct);

        await _refreshTokenService.RevokeAllAsync(userId, "admin", ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.AdminEmailChanged, "admin", "admin",
                userId, metadata: adminId.ToString(), tenantId: credential.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);

        LogAdminEmailChanged(_logger, adminId, userId);
    }

    private static CredentialDetail ToDetail(UserCredential c) => new(
        c.UserId, c.Email, c.Status, c.EmailConfirmed, c.MfaEnabled, c.MfaMethod,
        c.IsLockedOut(), c.LockoutEnd, c.FailedLoginAttempts,
        c.PasswordExpiresAt, c.PasswordChangedAt, c.MfaGracePeriodEndsAt,
        c.TenantId, c.CreatedAt, c.UpdatedAt);

    [LoggerMessage(2001, LogLevel.Warning, "Admin {AdminId} locked user {UserId}")]
    private static partial void LogAdminLocked(ILogger logger, Guid adminId, Guid userId);

    [LoggerMessage(2002, LogLevel.Information, "Admin {AdminId} unlocked user {UserId}")]
    private static partial void LogAdminUnlocked(ILogger logger, Guid adminId, Guid userId);

    [LoggerMessage(2003, LogLevel.Warning, "Admin {AdminId} reset MFA for user {UserId}")]
    private static partial void LogAdminMfaReset(ILogger logger, Guid adminId, Guid userId);

    [LoggerMessage(2004, LogLevel.Warning, "Admin {AdminId} expired password for user {UserId}")]
    private static partial void LogAdminPasswordExpired(ILogger logger, Guid adminId, Guid userId);

    [LoggerMessage(2005, LogLevel.Warning, "Admin {AdminId} revoked all sessions for user {UserId}")]
    private static partial void LogAdminSessionsRevoked(ILogger logger, Guid adminId, Guid userId);

    [LoggerMessage(2006, LogLevel.Warning, "Admin {AdminId} reset password for user {UserId}")]
    private static partial void LogAdminPasswordReset(ILogger logger, Guid adminId, Guid userId);

    [LoggerMessage(2007, LogLevel.Warning, "Admin {AdminId} changed email for user {UserId}")]
    private static partial void LogAdminEmailChanged(ILogger logger, Guid adminId, Guid userId);
}
