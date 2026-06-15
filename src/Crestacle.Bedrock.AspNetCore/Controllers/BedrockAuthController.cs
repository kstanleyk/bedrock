using Crestacle.Bedrock.AspNetCore.Authorization;
using Crestacle.Bedrock.AspNetCore.Middleware;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Bedrock.AspNetCore.Controllers;

[ApiController]
[Route("auth")]
public sealed class BedrockAuthController : ControllerBase
{
    private readonly ICredentialService _credentials;
    private readonly IRefreshTokenService _refreshTokens;
    private readonly ICredentialRepository _credentialRepo;
    private readonly IExternalLoginService _externalLogin;
    private readonly IInvitationService _invitations;
    private readonly ITokenService _tokenService;

    public BedrockAuthController(
        ICredentialService credentials,
        IRefreshTokenService refreshTokens,
        ICredentialRepository credentialRepo,
        IExternalLoginService externalLogin,
        IInvitationService invitations,
        ITokenService tokenService)
    {
        _credentials = credentials;
        _refreshTokens = refreshTokens;
        _credentialRepo = credentialRepo;
        _externalLogin = externalLogin;
        _invitations = invitations;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse>> Register(
        [FromBody] RegisterRequest request,
        CancellationToken ct)
    {
        await _credentials.RegisterAsync(Guid.NewGuid(), request.Email, request.Password, ct: ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("confirm-email")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse>> ConfirmEmail(
        [FromBody] ConfirmEmailRequest request,
        CancellationToken ct)
    {
        await _credentials.ConfirmEmailAsync(request.Token, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("resend-confirmation")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse>> ResendConfirmation(
        [FromBody] ResendConfirmationRequest request,
        CancellationToken ct)
    {
        await _credentials.ResendConfirmationAsync(request.Email, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<LoginResponse>>> Login(
        [FromBody] LoginRequest request,
        CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";
        var fingerprint = request.FingerprintHash ?? userAgent;

        var result = await _credentials.LoginFirstFactorAsync(
            request.Email, request.Password, ip, userAgent, fingerprint, ct);

        if (!result.Succeeded)
            return Unauthorized(BedrockResponse<LoginResponse>.Fail("Invalid credentials."));

        if (result.IsLockedOut)
        {
            Response.Headers["Retry-After"] =
                Math.Max(0, (int)(result.LockoutEnd!.Value - DateTime.UtcNow).TotalSeconds).ToString();
            return StatusCode(423, BedrockResponse<LoginResponse>.Fail("Account is locked."));
        }

        if (result.RequiresEnrollment)
        {
            return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
                AccessToken: null,
                RefreshToken: null,
                AccessTokenExpiresAt: null,
                RequiresMfa: false,
                ChallengeToken: null,
                ChallengeMethod: null,
                ChallengeExpiresAt: null,
                RequiresEnrollment: true,
                EnrollmentToken: result.EnrollmentToken,
                MfaGracePeriodEndsAt: null)));
        }

        if (result.Challenge is not null)
        {
            return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
                AccessToken: null,
                RefreshToken: null,
                AccessTokenExpiresAt: null,
                RequiresMfa: true,
                ChallengeToken: result.Challenge.ChallengeToken,
                ChallengeMethod: result.Challenge.Method,
                ChallengeExpiresAt: result.Challenge.ExpiresAt,
                RequiresEnrollment: false,
                EnrollmentToken: null,
                MfaGracePeriodEndsAt: null)));
        }

        var tokens = await _refreshTokens.IssueAsync(
            result.UserId, request.Email, [], ip, userAgent, fingerprint, ct: ct);

        SetRefreshCookie(tokens.RefreshToken);

        return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
            AccessToken: tokens.AccessToken,
            RefreshToken: null,
            AccessTokenExpiresAt: tokens.AccessTokenExpiresAt,
            RequiresMfa: false,
            ChallengeToken: null,
            ChallengeMethod: null,
            ChallengeExpiresAt: null,
            RequiresEnrollment: false,
            EnrollmentToken: null,
            MfaGracePeriodEndsAt: result.MfaGracePeriodEndsAt)));
    }

    [HttpPost("verify-2fa")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<TokenResponse>>> VerifyMfa(
        [FromBody] VerifyMfaRequest request,
        CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";
        var fingerprint = request.FingerprintHash ?? userAgent;

        var userId = await _credentials.VerifyMfaAsync(
            request.ChallengeToken, request.Code, ip, userAgent, ct);

        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct);
        var email = credential?.Email ?? string.Empty;

        var tokens = await _refreshTokens.IssueAsync(
            userId, email, [], ip, userAgent, fingerprint, ct: ct);

        SetRefreshCookie(tokens.RefreshToken);

        return Ok(BedrockResponse<TokenResponse>.Ok(
            new TokenResponse(tokens.AccessToken, null, tokens.AccessTokenExpiresAt)));
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<TokenResponse>>> Refresh(
        [FromBody] RefreshRequest request,
        CancellationToken ct)
    {
        var refreshToken = Request.Cookies["omni_refresh"];
        if (string.IsNullOrEmpty(refreshToken))
            return Unauthorized(BedrockResponse<TokenResponse>.Fail("No refresh token."));

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";
        var fingerprint = request.FingerprintHash ?? userAgent;

        var tokens = await _refreshTokens.RefreshAsync(
            refreshToken, ip, userAgent, fingerprint, ct);

        SetRefreshCookie(tokens.RefreshToken);

        return Ok(BedrockResponse<TokenResponse>.Ok(
            new TokenResponse(tokens.AccessToken, null, tokens.AccessTokenExpiresAt)));
    }

    [HttpPost("revoke")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse>> Revoke(
        [FromBody] RevokeRequest request,
        CancellationToken ct)
    {
        var refreshToken = Request.Cookies["omni_refresh"] ?? request.RefreshToken;
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!string.IsNullOrEmpty(refreshToken))
            await _refreshTokens.RevokeAsync(refreshToken, ip, ct: ct);
        DeleteRefreshCookie();
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("logout")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse>> Logout(CancellationToken ct)
    {
        var refreshToken = Request.Cookies["omni_refresh"];
        if (!string.IsNullOrEmpty(refreshToken))
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await _refreshTokens.RevokeAsync(refreshToken, ip, ct: ct);
        }
        DeleteRefreshCookie();
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("confirm-email-change")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse>> ConfirmEmailChange(
        [FromBody] ConfirmEmailChangeRequest request,
        CancellationToken ct)
    {
        await _credentials.ConfirmEmailChangeAsync(request.TokenHash, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("magic-link")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse>> RequestMagicLink(
        [FromBody] MagicLinkRequest request,
        CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";

        await _credentials.RequestMagicLinkAsync(request.Email, ip, userAgent, ct);
        return Ok(BedrockResponse.Ok());
    }

    [HttpPost("external-login")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<LoginResponse>>> ExternalLogin(
        [FromBody] ExternalLoginRequest request,
        CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";

        var result = await _externalLogin.ExternalLoginAsync(
            request.Provider, request.ProviderToken, ip, userAgent, ct);

        SetRefreshCookie(result.Tokens!.RefreshToken);

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

    [HttpPost("accept-invitation")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<LoginResponse>>> AcceptInvitation(
        [FromBody] AcceptInvitationRequest request,
        CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";

        var tokens = await _invitations.AcceptInvitationAsync(
            request.TokenHash, request.Password, ip, userAgent, ct);

        SetRefreshCookie(tokens.RefreshToken);

        return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
            AccessToken: tokens.AccessToken,
            RefreshToken: null,
            AccessTokenExpiresAt: tokens.AccessTokenExpiresAt,
            RequiresMfa: false,
            ChallengeToken: null,
            ChallengeMethod: null,
            ChallengeExpiresAt: null,
            RequiresEnrollment: false,
            EnrollmentToken: null,
            MfaGracePeriodEndsAt: null)));
    }

    [HttpPost("magic-link/verify")]
    [AllowAnonymous]
    public async Task<ActionResult<BedrockResponse<LoginResponse>>> VerifyMagicLink(
        [FromBody] VerifyMagicLinkRequest request,
        CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(userAgent)) userAgent = "unknown";
        var fingerprint = request.FingerprintHash ?? userAgent;

        var result = await _credentials.VerifyMagicLinkAsync(request.TokenHash, ip, userAgent, ct);

        if (!result.Succeeded)
            return Unauthorized(BedrockResponse<LoginResponse>.Fail("Invalid or expired magic link."));

        if (result.IsLockedOut)
        {
            Response.Headers["Retry-After"] =
                Math.Max(0, (int)(result.LockoutEnd!.Value - DateTime.UtcNow).TotalSeconds).ToString();
            return StatusCode(423, BedrockResponse<LoginResponse>.Fail("Account is locked."));
        }

        if (result.RequiresEnrollment)
        {
            return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
                AccessToken: null,
                RefreshToken: null,
                AccessTokenExpiresAt: null,
                RequiresMfa: false,
                ChallengeToken: null,
                ChallengeMethod: null,
                ChallengeExpiresAt: null,
                RequiresEnrollment: true,
                EnrollmentToken: result.EnrollmentToken,
                MfaGracePeriodEndsAt: null)));
        }

        if (result.Challenge is not null)
        {
            return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
                AccessToken: null,
                RefreshToken: null,
                AccessTokenExpiresAt: null,
                RequiresMfa: true,
                ChallengeToken: result.Challenge.ChallengeToken,
                ChallengeMethod: result.Challenge.Method,
                ChallengeExpiresAt: result.Challenge.ExpiresAt,
                RequiresEnrollment: false,
                EnrollmentToken: null,
                MfaGracePeriodEndsAt: null)));
        }

        var credential = await _credentialRepo.GetByUserIdAsync(result.UserId, ct);
        var email = credential?.Email ?? string.Empty;

        var tokens = await _refreshTokens.IssueAsync(
            result.UserId, email, [], ip, userAgent, fingerprint, ct: ct);

        SetRefreshCookie(tokens.RefreshToken);

        return Ok(BedrockResponse<LoginResponse>.Ok(new LoginResponse(
            AccessToken: tokens.AccessToken,
            RefreshToken: null,
            AccessTokenExpiresAt: tokens.AccessTokenExpiresAt,
            RequiresMfa: false,
            ChallengeToken: null,
            ChallengeMethod: null,
            ChallengeExpiresAt: null,
            RequiresEnrollment: false,
            EnrollmentToken: null,
            MfaGracePeriodEndsAt: result.MfaGracePeriodEndsAt)));
    }

    /// <summary>
    /// Issues a short-lived enrollment token so an authenticated user can voluntarily
    /// enroll MFA before their grace period expires. Returns 409 if MFA is already enabled.
    /// </summary>
    [HttpPost("request-enrollment")]
    [Authorize(Policy = BedrockPolicyNames.Default)]
    public async Task<ActionResult<BedrockResponse<RequestEnrollmentResponse>>> RequestEnrollment(
        CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)!.Value);
        var credential = await _credentialRepo.GetByUserIdAsync(userId, ct);

        if (credential is { MfaEnabled: true })
            return Conflict(BedrockResponse<RequestEnrollmentResponse>.Fail("MFA is already enabled."));

        var token = _tokenService.GenerateEnrollmentToken(userId);
        return Ok(BedrockResponse<RequestEnrollmentResponse>.Ok(new RequestEnrollmentResponse(token)));
    }

    private void SetRefreshCookie(string token) =>
        Response.Cookies.Append("omni_refresh", token, new CookieOptions
        {
            HttpOnly = true,
            Secure   = true,
            SameSite = SameSiteMode.Strict,
            Expires  = DateTimeOffset.UtcNow.AddDays(7),
            Path     = "/api/v1/auth",
        });

    private void DeleteRefreshCookie() =>
        Response.Cookies.Delete("omni_refresh", new CookieOptions { Path = "/api/v1/auth" });
}
