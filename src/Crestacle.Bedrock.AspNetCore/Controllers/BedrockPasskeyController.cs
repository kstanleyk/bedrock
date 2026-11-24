using System.Security.Claims;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Authorization;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Controllers;

[ApiController]
[Route("passkeys")]
public sealed class BedrockPasskeyController : ControllerBase
{
    private readonly IPasskeyService _passkeys;
    private readonly BedrockOptions _options;
    private readonly IBedrockRealmProvider _realmProvider;

    public BedrockPasskeyController(IPasskeyService passkeys, IOptions<BedrockOptions> options, IBedrockRealmProvider realmProvider)
    {
        _passkeys = passkeys;
        _options = options.Value;
        _realmProvider = realmProvider;
    }

    // -------------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------------

    [HttpPost("register/begin")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse<JsonElement>>> BeginRegistration(CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var username = User.FindFirstValue("email") ?? userId.ToString();

        var optionsJson = await _passkeys.BeginRegistrationAsync(userId, username, ct);
        var options = JsonSerializer.Deserialize<JsonElement>(optionsJson);
        return Ok(BedrockResponse<JsonElement>.Ok(options));
    }

    [HttpPost("register/complete")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse>> CompleteRegistration(
        [FromBody] CompletePasskeyRegistrationRequest request,
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _passkeys.CompleteRegistrationAsync(userId, request.AttestationResponse, request.FriendlyName, ct);
        return Ok(BedrockResponse.Ok());
    }

    // -------------------------------------------------------------------------
    // Credential management
    // -------------------------------------------------------------------------

    [HttpGet]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse<IReadOnlyList<PasskeyInfoResponse>>>> ListPasskeys(
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var passkeys = await _passkeys.GetPasskeysAsync(userId, ct);
        var response = passkeys
            .Select(p => new PasskeyInfoResponse(p.Id, p.FriendlyName, p.CreatedAt))
            .ToList();
        return Ok(BedrockResponse<IReadOnlyList<PasskeyInfoResponse>>.Ok(response));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse>> DeletePasskey(Guid id, CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        await _passkeys.DeletePasskeyAsync(id, userId, ct);
        return Ok(BedrockResponse.Ok());
    }

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    [HttpPost("authenticate/begin")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<JsonElement>>> BeginAuthentication(
        [FromBody] BeginPasskeyAuthenticationRequest request,
        CancellationToken ct)
    {
        var optionsJson = await _passkeys.BeginAuthenticationAsync(request.Email, ct);
        var options = JsonSerializer.Deserialize<JsonElement>(optionsJson);
        return Ok(BedrockResponse<JsonElement>.Ok(options));
    }

    [HttpPost("authenticate/complete")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<LoginResponse>>> CompleteAuthentication(
        [FromBody] CompletePasskeyAuthenticationRequest request,
        CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";

        var result = await _passkeys.CompleteAuthenticationAsync(
            request.AssertionResponse, ip, userAgent, ct);

        // Name/Expires realm-resolved (1-BE-09-f) via the SAME IBedrockRealmProvider
        // BedrockAuthController uses -- Expires previously hardcoded AddDays(7) regardless
        // of the real configured TTL (BedrockAuthController.SetRefreshCookie's own remarks
        // cover why that's a real bug, not just a passkey-specific inconsistency).
        //
        // SameSite now reads _options.Session.RefreshCookieSameSite, matching
        // BedrockAuthController.SetRefreshCookie. It previously hardcoded Strict
        // unconditionally, which silently broke passkey-based session restore in the exact
        // cross-site scenario the configurable policy exists for (see docs/quality-roadmap.md D2).
        var realm = _realmProvider.Resolve(HttpContext.Request.Host.Host);
        Response.Cookies.Append(
            realm?.RefreshCookieName ?? _options.Session.RefreshCookieName,
            result.Tokens!.RefreshToken,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = ToAspNetSameSite(_options.Session.RefreshCookieSameSite),
                Expires = DateTimeOffset.UtcNow.Add(realm?.RefreshTokenExpiry ?? _options.Jwt.RefreshTokenExpiry),
                Path = _options.Session.RefreshCookiePath,
            });

        return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
            AccessToken: result.Tokens.AccessToken,
            RefreshToken: null,
            AccessTokenExpiresAt: result.Tokens.AccessTokenExpiresAt,
            RequiresMfa: false,
            ChallengeToken: null,
            ChallengeMethod: null,
            ChallengeExpiresAt: null,
            RequiresEnrollment: false,
            EnrollmentToken: null,
            MfaGracePeriodEndsAt: null)));
    }

    private static SameSiteMode ToAspNetSameSite(RefreshCookieSameSitePolicy policy) => policy switch
    {
        RefreshCookieSameSitePolicy.Strict => SameSiteMode.Strict,
        RefreshCookieSameSitePolicy.Lax => SameSiteMode.Lax,
        RefreshCookieSameSitePolicy.None => SameSiteMode.None,
        _ => throw new ArgumentOutOfRangeException(nameof(policy), policy, null),
    };
}
