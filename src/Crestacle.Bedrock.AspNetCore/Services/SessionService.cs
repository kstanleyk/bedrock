using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Microsoft.Extensions.Logging;

namespace Crestacle.Bedrock.AspNetCore.Services;

internal sealed partial class SessionService : ISessionService
{
    private const string RevokedCacheKeyPrefix = "Bedrock:revoked:";

    private readonly ISessionRepository _sessionRepo;
    private readonly IRefreshTokenRepository _refreshTokenRepo;
    private readonly IAuditRepository _auditRepo;
    private readonly IBedrockUnitOfWork _unitOfWork;
    private readonly IBedrockCache _cache;
    private readonly ILogger<SessionService> _logger;

    public SessionService(
        ISessionRepository sessionRepo,
        IRefreshTokenRepository refreshTokenRepo,
        IAuditRepository auditRepo,
        IBedrockUnitOfWork unitOfWork,
        IBedrockCache cache,
        ILogger<SessionService> logger)
    {
        _sessionRepo = sessionRepo;
        _refreshTokenRepo = refreshTokenRepo;
        _auditRepo = auditRepo;
        _unitOfWork = unitOfWork;
        _cache = cache;
        _logger = logger;
    }

    public Task<IReadOnlyList<Session>> GetActiveSessionsAsync(Guid userId, CancellationToken ct = default)
        => _sessionRepo.GetActiveByUserAsync(userId, ct);

    public async Task RevokeSessionAsync(
        Guid sessionId,
        Guid requestingUserId,
        string ip,
        CancellationToken ct = default)
    {
        var session = await _sessionRepo.GetByIdAsync(sessionId, ct)
            ?? throw new BedrockNotFoundException("Session not found.");

        if (session.UserId != requestingUserId)
            throw new BedrockForbiddenException("You do not have permission to revoke this session.");

        if (!session.IsActive)
            return;

        var refreshToken = await _refreshTokenRepo.GetByHashAsync(session.TokenHash, ct);
        if (refreshToken is not null && refreshToken.IsActive)
        {
            refreshToken.Revoke(ip);
            await _refreshTokenRepo.UpdateAsync(refreshToken, ct);
        }

        session.Revoke(ip);
        await _sessionRepo.UpdateAsync(session, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.SessionRevoked, ip, "unknown",
                session.UserId, tenantId: session.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);
        LogSessionRevoked(_logger, sessionId, session.UserId, session.TenantId);

        // Blacklist the still-live access token so an in-flight request using it is rejected
        // immediately, instead of staying valid until its natural (short but nonzero) expiry --
        // same mechanism RefreshTokenService.RevokeAsync/RevokeAllAsync already use.
        await BlacklistAccessTokenAsync(session, ct);
    }

    public async Task RevokeAllSessionsAsync(Guid userId, string ip, CancellationToken ct = default)
    {
        var activeSessions = await _sessionRepo.GetActiveByUserAsync(userId, ct);

        await _refreshTokenRepo.RevokeAllForUserAsync(userId, ip, ct);
        await _sessionRepo.RevokeAllForUserAsync(userId, ip, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.SessionRevoked, ip, "unknown", userId), ct);
        await _unitOfWork.SaveChangesAsync(ct);
        LogAllSessionsRevoked(_logger, userId);

        foreach (var session in activeSessions)
            await BlacklistAccessTokenAsync(session, ct);
    }

    private async Task BlacklistAccessTokenAsync(Session session, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(session.AccessTokenJti) || session.AccessTokenExpiresAt is not { } expiresAt)
            return;

        var remaining = expiresAt - DateTime.UtcNow;
        if (remaining > TimeSpan.Zero)
            await _cache.SetAsync(RevokedCacheKeyPrefix + session.AccessTokenJti, "1", remaining, ct);
    }

    [LoggerMessage(3001, LogLevel.Information, "Session revoked: sessionId={SessionId} userId={UserId} tenant={TenantId}")]
    private static partial void LogSessionRevoked(ILogger logger, Guid sessionId, Guid userId, string? tenantId);

    [LoggerMessage(3002, LogLevel.Information, "All sessions revoked: userId={UserId}")]
    private static partial void LogAllSessionsRevoked(ILogger logger, Guid userId);
}
