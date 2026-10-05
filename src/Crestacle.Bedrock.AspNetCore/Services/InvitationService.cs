using System.Security.Cryptography;
using System.Text;
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

internal sealed partial class InvitationService : IInvitationService
{
    private readonly IInvitationRepository _invitationRepo;
    private readonly ICredentialService _credentialService;
    private readonly ICredentialRepository _credentialRepo;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IAuditRepository _auditRepo;
    private readonly IBedrockUnitOfWork _unitOfWork;
    private readonly IEmailSender _emailSender;
    private readonly BedrockOptions _options;
    private readonly ILogger<InvitationService> _logger;

    public InvitationService(
        IInvitationRepository invitationRepo,
        ICredentialService credentialService,
        ICredentialRepository credentialRepo,
        IRefreshTokenService refreshTokenService,
        IAuditRepository auditRepo,
        IBedrockUnitOfWork unitOfWork,
        IEmailSender emailSender,
        IOptions<BedrockOptions> options,
        ILogger<InvitationService> logger)
    {
        _invitationRepo = invitationRepo;
        _credentialService = credentialService;
        _credentialRepo = credentialRepo;
        _refreshTokenService = refreshTokenService;
        _auditRepo = auditRepo;
        _unitOfWork = unitOfWork;
        _emailSender = emailSender;
        _options = options.Value;
        _logger = logger;
    }

    public async Task CreateInvitationAsync(
        Guid? invitedByUserId,
        string targetEmail,
        string? roleHint,
        string ipAddress,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetEmail);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);
        var expiresAt = DateTime.UtcNow.Add(_options.TokenExpiry.Invitation);

        var invitation = Invitation.Create(tokenHash, targetEmail, invitedByUserId, roleHint, expiresAt);
        await _invitationRepo.AddAsync(invitation, ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.InvitationCreated, ipAddress, "admin",
                invitedByUserId, metadata: targetEmail), ct);

        await _unitOfWork.SaveChangesAsync(ct);

        var url = BuildInvitationUrl(rawToken);
        await _emailSender.SendAsync(targetEmail, "You've been invited", $"Accept your invitation: {url}", ct);

        LogInvitationCreated(_logger, targetEmail, invitedByUserId);
    }

    public async Task<TokenPair> AcceptInvitationAsync(
        string rawToken,
        string password,
        string ipAddress,
        string userAgent,
        CancellationToken ct = default)
    {
        var tokenHash = ComputeTokenHash(rawToken);
        var invitation = await _invitationRepo.GetByHashAsync(tokenHash, ct);
        if (invitation is null || !invitation.IsValid)
            throw new BedrockValidationException("Invitation is invalid or has expired.");

        var newUserId = Guid.NewGuid();

        // RegisterAsync validates password, hashes it, creates the credential in
        // PendingVerification state, and saves. The verification email is a no-op
        // because invitation acceptance implies the email is already confirmed.
        await _credentialService.RegisterAsync(newUserId, invitation.TargetEmail, password, ct: ct);

        // Auto-confirm: load the freshly persisted credential and mark it Active.
        var credential = await _credentialRepo.GetByEmailAsync(invitation.TargetEmail, ct);
        credential!.ConfirmEmail();
        await _credentialRepo.UpdateAsync(credential, ct);

        invitation.Accept();
        await _invitationRepo.UpdateAsync(invitation, ct);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.InvitationAccepted, ipAddress, userAgent,
                newUserId, metadata: invitation.TargetEmail), ct);

        await _unitOfWork.SaveChangesAsync(ct);

        LogInvitationAccepted(_logger, invitation.TargetEmail, newUserId);

        return await _refreshTokenService.IssueAsync(
            newUserId, invitation.TargetEmail, [], ipAddress, userAgent, userAgent, ct: ct);
    }

    private string BuildInvitationUrl(string rawToken)
    {
        var baseUrl = _options.Email.FrontendBaseUrl.TrimEnd('/');
        return $"{baseUrl}{_options.Email.InvitationPath}?token={Uri.EscapeDataString(rawToken)}";
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

    [LoggerMessage(3001, LogLevel.Information, "Invitation created for {TargetEmail} by admin {AdminId}")]
    private static partial void LogInvitationCreated(ILogger logger, string targetEmail, Guid? adminId);

    [LoggerMessage(3002, LogLevel.Information, "Invitation accepted for {TargetEmail} → new user {UserId}")]
    private static partial void LogInvitationAccepted(ILogger logger, string targetEmail, Guid userId);
}
