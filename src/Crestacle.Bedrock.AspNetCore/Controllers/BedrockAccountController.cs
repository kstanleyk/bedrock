using System.Security.Claims;
using Crestacle.Bedrock.AspNetCore.Authorization;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Bedrock.AspNetCore.Controllers;

[ApiController]
[Route("account")]
public sealed class BedrockAccountController : ControllerBase
{
    private readonly ICredentialService _credentials;
    private readonly IConsentService _consent;
    private readonly IExternalLoginService _externalLogin;

    public BedrockAccountController(
        ICredentialService credentials,
        IConsentService consent,
        IExternalLoginService externalLogin)
    {
        _credentials = credentials;
        _consent = consent;
        _externalLogin = externalLogin;
    }

    [HttpDelete("")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse>> DeleteAccount(CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _credentials.AnonymizeAsync(userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("consent")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse>> RecordConsent(
        [FromBody] RecordConsentRequest request,
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";

        await _consent.RecordConsentAsync(userId, request.PolicyType, request.PolicyVersion, ip, userAgent, ct: ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpGet("consent")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse<IReadOnlyList<ConsentRecordResponse>>>> GetConsentHistory(
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var history = await _consent.GetConsentHistoryAsync(userId, ct);
        var response = history
            .Select(r => new ConsentRecordResponse(r.Id, r.PolicyType, r.PolicyVersion, r.AcceptedAt, r.IpAddress))
            .ToList();
        return Ok(BedrockResponse<IReadOnlyList<ConsentRecordResponse>>.Ok(response));
    }

    [HttpPost("request-email-change")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse>> RequestEmailChange(
        [FromBody] RequestEmailChangeRequest request,
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";

        await _credentials.RequestEmailChangeAsync(userId, request.NewEmail, ip, userAgent, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("link-external")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse>> LinkExternalIdentity(
        [FromBody] LinkExternalIdentityRequest request,
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _externalLogin.LinkExternalIdentityAsync(userId, request.Provider, request.ProviderToken, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpDelete("external/{provider}")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse>> UnlinkExternalIdentity(
        string provider,
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _externalLogin.UnlinkExternalIdentityAsync(userId, provider, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpGet("external")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse<IReadOnlyList<ExternalIdentityResponse>>>> GetLinkedIdentities(
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var identities = await _externalLogin.GetLinkedIdentitiesAsync(userId, ct);
        var response = identities
            .Select(e => new ExternalIdentityResponse(e.Id, e.Provider, e.CreatedAt))
            .ToList();
        return Ok(BedrockResponse<IReadOnlyList<ExternalIdentityResponse>>.Ok(response));
    }
}

[ApiController]
[Route("admin")]
[Authorize(Policy = BedrockPolicyNames.Admin)]
public sealed class BedrockAdminController : ControllerBase
{
    private readonly ICredentialService _credentials;
    private readonly IBedrockAdminService _admin;
    private readonly IInvitationService _invitations;

    public BedrockAdminController(
        ICredentialService credentials,
        IBedrockAdminService admin,
        IInvitationService invitations)
    {
        _credentials = credentials;
        _admin = admin;
        _invitations = invitations;
    }

    [HttpDelete("users/{userId:guid}/anonymize")]
    public async Task<ActionResult<BedrockResponse>> AnonymizeUser(Guid userId, CancellationToken ct)
    {
        await _credentials.AnonymizeAsync(userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpGet("users")]
    public async Task<ActionResult<BedrockResponse<PagedResult<CredentialSummary>>>> GetUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        var result = await _admin.GetUsersAsync(page, pageSize, ct);
        return Ok(BedrockResponse<PagedResult<CredentialSummary>>.Ok(result));
    }

    [HttpGet("users/{userId:guid}")]
    public async Task<ActionResult<BedrockResponse<CredentialDetail>>> GetUser(Guid userId, CancellationToken ct)
    {
        var detail = await _admin.GetUserAsync(userId, ct);
        return Ok(BedrockResponse<CredentialDetail>.Ok(detail));
    }

    [HttpPost("users/{userId:guid}/lock")]
    public async Task<ActionResult<BedrockResponse>> LockUser(Guid userId, CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _admin.LockUserAsync(adminId, userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("users/{userId:guid}/unlock")]
    public async Task<ActionResult<BedrockResponse>> UnlockUser(Guid userId, CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _admin.UnlockUserAsync(adminId, userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("users/{userId:guid}/reset-mfa")]
    public async Task<ActionResult<BedrockResponse>> ResetMfa(Guid userId, CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _admin.ResetMfaAsync(adminId, userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("users/{userId:guid}/expire-password")]
    public async Task<ActionResult<BedrockResponse>> ExpirePassword(Guid userId, CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _admin.ExpirePasswordAsync(adminId, userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpDelete("users/{userId:guid}/sessions")]
    public async Task<ActionResult<BedrockResponse>> RevokeAllSessions(Guid userId, CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _admin.RevokeAllSessionsAsync(adminId, userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("users/{userId:guid}/reset-password")]
    public async Task<ActionResult<BedrockResponse>> ResetPassword(
        Guid userId, [FromBody] AdminResetPasswordRequest request, CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _admin.ResetPasswordAsync(adminId, userId, request.NewPassword, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("users/{userId:guid}/change-email")]
    public async Task<ActionResult<BedrockResponse>> ChangeEmail(
        Guid userId, [FromBody] AdminChangeEmailRequest request, CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _admin.AdminChangeEmailAsync(adminId, userId, request.NewEmail, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("invitations")]
    public async Task<ActionResult<BedrockResponse>> CreateInvitation(
        [FromBody] CreateInvitationRequest request,
        CancellationToken ct)
    {
        var adminId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await _invitations.CreateInvitationAsync(adminId, request.TargetEmail, request.RoleHint, ip, ct);
        return Ok(BedrockResponse.Ok());
    }
}
