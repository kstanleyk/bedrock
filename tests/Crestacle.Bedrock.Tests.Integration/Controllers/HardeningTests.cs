using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Crestacle.Bedrock.Core.Realm;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

/// <summary>
/// Phase 10 hardening tests: end-to-end flows, token rotation, session limits,
/// scope enforcement, and security invariants.
/// </summary>
public sealed class HardeningTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";

    public HardeningTests()
    {
        _server = new BedrockTestServer(
            configureServices: services => services.AddSingleton<IEmailSender>(_emailSender));
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // Full end-to-end flow
    // -------------------------------------------------------------------------

    [Fact]
    public async Task EndToEnd_RegisterConfirmLoginRefreshRevoke_Succeeds()
    {
        var email = "e2e-full@example.com";

        // Register
        var reg = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));
        reg.StatusCode.Should().Be(HttpStatusCode.OK);

        // Confirm email — the real raw token a user would receive (not the stored hash).
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);
        var confirm = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest(rawToken));
        confirm.StatusCode.Should().Be(HttpStatusCode.OK);

        // Login → get access token (body) + refresh token (HttpOnly cookie only)
        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        loginResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginBody = await ReadAsync<BedrockResponse<LoginResponse>>(loginResp);
        loginBody.Data!.AccessToken.Should().NotBeNullOrEmpty();
        loginBody.Data.RefreshToken.Should().BeNull();
        var refresh1 = loginResp.GetRefreshCookieValue();
        refresh1.Should().NotBeNullOrEmpty();

        // Use access token to access a protected endpoint
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", loginBody.Data.AccessToken);
        var sessions = await _client.GetAsync("/api/bedrock/sessions");
        sessions.StatusCode.Should().Be(HttpStatusCode.OK);
        _client.DefaultRequestHeaders.Authorization = null;

        // Refresh → get new token pair; the cookie must rotate to a new value
        _client.SetRefreshCookie(refresh1);
        var refreshResp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        refreshResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var refreshBody = await ReadAsync<BedrockResponse<TokenResponse>>(refreshResp);
        refreshBody.Data!.AccessToken.Should().NotBeNullOrEmpty();
        var refresh2 = refreshResp.GetRefreshCookieValue();
        refresh2.Should().NotBeNullOrEmpty();
        refresh2.Should().NotBe(refresh1);

        // Old refresh token must be rejected (rotated)
        _client.SetRefreshCookie(refresh1);
        var oldRefreshResp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        oldRefreshResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // Revoke the new token
        _client.SetRefreshCookie(refresh2);
        var revokeResp = await _client.PostAsJsonAsync("/api/bedrock/auth/revoke", new RevokeRequest());
        revokeResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Revoked token must be rejected
        _client.SetRefreshCookie(refresh2);
        var revokedRefreshResp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        _client.SetRefreshCookie(null);
        revokedRefreshResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // Refresh token rotation chain
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RefreshRotationChain_ThreeRotations_EachGeneratesUniqueToken()
    {
        var email = "rotation-chain@example.com";
        await RegisterAndActivateAsync(email);
        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var initialCookie = loginResp.GetRefreshCookieValue();
        initialCookie.Should().NotBeNullOrEmpty();

        var tokens = new List<string> { initialCookie! };

        // Rotate 3 times; each must succeed and produce a distinct refresh token
        for (var i = 0; i < 3; i++)
        {
            _client.SetRefreshCookie(tokens[^1]);
            var resp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
            resp.StatusCode.Should().Be(HttpStatusCode.OK);
            var rotated = resp.GetRefreshCookieValue();
            rotated.Should().NotBeNullOrEmpty();
            tokens.Add(rotated!);
        }
        _client.SetRefreshCookie(null);

        tokens.Should().OnlyHaveUniqueItems();

        // All previous tokens must be rejected
        foreach (var stale in tokens.SkipLast(1))
        {
            _client.SetRefreshCookie(stale);
            var reject = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
            reject.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
        _client.SetRefreshCookie(null);
    }

    // -------------------------------------------------------------------------
    // H13/D17 — replaying a stale (already-rotated) refresh token must revoke the LIVE
    // TIP of the rotation chain too, not just reject the stale token itself.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RefreshReuseDetection_ReplayingStaleToken_RevokesLiveTipToo()
    {
        var email = "reuse-detection-live-tip@example.com";
        await RegisterAndActivateAsync(email);

        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var token0 = loginResp.GetRefreshCookieValue();
        token0.Should().NotBeNullOrEmpty();

        // Rotate once: token0 -> token1
        _client.SetRefreshCookie(token0);
        var rotate1 = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        rotate1.StatusCode.Should().Be(HttpStatusCode.OK);
        var token1 = rotate1.GetRefreshCookieValue();
        token1.Should().NotBeNullOrEmpty();

        // Rotate again: token1 -> token2. token2 is now the LIVE TIP of the chain.
        _client.SetRefreshCookie(token1);
        var rotate2 = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        rotate2.StatusCode.Should().Be(HttpStatusCode.OK);
        var liveTip = rotate2.GetRefreshCookieValue();
        liveTip.Should().NotBeNullOrEmpty();

        // Replay the now-stale token0. It was already rotated away once (ReplacedByTokenHash is
        // set), so this is the reuse-of-an-already-rotated-token case, which must revoke the
        // WHOLE downstream chain -- including the still-active live tip -- not merely reject
        // this one stale token.
        _client.SetRefreshCookie(token0);
        var replay = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        replay.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // The live tip -- which was perfectly valid a moment ago -- must now ALSO be rejected.
        _client.SetRefreshCookie(liveTip);
        var liveTipAttempt = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        _client.SetRefreshCookie(null);

        liveTipAttempt.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "replaying a stale, already-rotated token must revoke the live tip of the " +
                     "rotation chain too, not just reject the stale token itself");
    }

    // -------------------------------------------------------------------------
    // H13/D19 — an oversized User-Agent must be truncated to fit device_fingerprint
    // (varchar(128)), not bubble up as an unhandled DB exception.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Login_OversizedUserAgent_FingerprintTruncatedNotRejected()
    {
        var email = "oversized-ua@example.com";
        await RegisterAndActivateAsync(email);

        // Far beyond the 128-char device_fingerprint column (and beyond headless Chrome's own
        // 129-char default UA, the real-world case this guards against).
        var longUserAgent = new string('A', 300);

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/bedrock/auth/login")
        {
            // FingerprintHash intentionally omitted -- the controller falls back to the raw
            // User-Agent header in that case, which is the path that must be truncated.
            Content = JsonContent.Create(new LoginRequest(email, ValidPassword)),
        };
        request.Headers.TryAddWithoutValidation("User-Agent", longUserAgent);

        var resp = await _client.SendAsync(request);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "an oversized User-Agent must be truncated to fit device_fingerprint, " +
                     "not surface as a 500 from a DB-level column-length violation");

        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        var session = _server.DbContext.Sessions
            .Where(s => s.UserId == userId)
            .OrderByDescending(s => s.CreatedAt)
            .First();

        session.DeviceFingerprint.Length.Should().BeLessOrEqualTo(128);
        session.DeviceFingerprint.Should().Be(longUserAgent[..128]);
    }

    // -------------------------------------------------------------------------
    // H13/D18 — refresh-cookie settings resolution across realms and SameSite policies.
    // ResolveRefreshCookieSettings (name + expiry) is realm-scoped; SameSite is a global
    // BedrockOptions setting applied regardless of which realm handled the request.
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(RefreshCookieSameSitePolicy.Strict)]
    [InlineData(RefreshCookieSameSitePolicy.Lax)]
    public async Task Login_MultiRealmHost_ResolvesPerRealmCookieNameAndExpiry_WithConfiguredSameSite(
        RefreshCookieSameSitePolicy sameSite)
    {
        var emailSender = new CapturingEmailSender();
        using var server = new BedrockTestServer(
            configureOptions: opts => opts.Session.RefreshCookieSameSite = sameSite,
            configureServices: services =>
            {
                services.AddSingleton<IEmailSender>(emailSender);
                services.AddSingleton<IBedrockRealmProvider, TestMultiRealmProvider>();
            });
        var client = server.Client;

        foreach (var (host, realm) in new[]
                 {
                     ("realm-a.test", TestMultiRealmProvider.RealmA),
                     ("realm-b.test", TestMultiRealmProvider.RealmB),
                 })
        {
            var email = $"realm-test-{host}@example.com";
            await client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));
            var rawToken = CapturingEmailSender.ExtractToken(emailSender.LastBodyFor(email)!);
            await client.PostAsJsonAsync("/api/bedrock/auth/confirm-email", new ConfirmEmailRequest(rawToken));

            var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/api/bedrock/auth/login")
            {
                Content = JsonContent.Create(new LoginRequest(email, ValidPassword)),
            };
            loginRequest.Headers.Host = host;

            var beforeLogin = DateTimeOffset.UtcNow;
            var loginResp = await client.SendAsync(loginRequest);
            loginResp.StatusCode.Should().Be(HttpStatusCode.OK);

            var cookieHeader = GetFullSetCookieHeader(loginResp, realm.RefreshCookieName);
            cookieHeader.Should().NotBeNull(
                because: $"realm '{realm.Name}' resolved from Host '{host}' must set its own configured cookie name");

            cookieHeader!.ToLowerInvariant().Should().Contain(
                $"samesite={sameSite.ToString().ToLowerInvariant()}",
                because: "SameSite is a global BedrockOptions.Session setting, not realm-scoped -- " +
                          "it must match this server's configured policy regardless of which realm handled the request");

            var expiresMatch = Regex.Match(cookieHeader, "expires=([^;]+)", RegexOptions.IgnoreCase);
            expiresMatch.Success.Should().BeTrue(because: "the refresh cookie must carry an explicit Expires attribute");
            var expires = DateTimeOffset.Parse(expiresMatch.Groups[1].Value);
            expires.Should().BeCloseTo(beforeLogin.Add(realm.RefreshTokenExpiry), TimeSpan.FromMinutes(1),
                because: $"realm '{realm.Name}' overrides RefreshTokenExpiry; the cookie's Expires must follow " +
                          "that realm value, not the base BedrockOptions default");
        }
    }

    /// <summary>Maps two fixed hosts to two distinct realms; any other host resolves to null (base-options fallback).</summary>
    private sealed class TestMultiRealmProvider : IBedrockRealmProvider
    {
        public static readonly BedrockRealm RealmA = new()
        {
            Name = "realm-a",
            MfaMandatory = false,
            MfaGracePeriodDays = 0,
            RefreshCookieName = "realm_a_refresh",
            RefreshTokenExpiry = TimeSpan.FromHours(1),
            FrontendBaseUrl = "https://realm-a.test",
        };

        public static readonly BedrockRealm RealmB = new()
        {
            Name = "realm-b",
            MfaMandatory = false,
            MfaGracePeriodDays = 0,
            RefreshCookieName = "realm_b_refresh",
            RefreshTokenExpiry = TimeSpan.FromHours(2),
            FrontendBaseUrl = "https://realm-b.test",
        };

        public BedrockRealm? Resolve(string? host) => host switch
        {
            "realm-a.test" => RealmA,
            "realm-b.test" => RealmB,
            _ => null,
        };
    }

    private static string? GetFullSetCookieHeader(HttpResponseMessage response, string cookieName)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var headers))
            return null;
        return headers.FirstOrDefault(h => h.StartsWith($"{cookieName}=", StringComparison.Ordinal));
    }

    // -------------------------------------------------------------------------
    // Concurrent session limit
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ConcurrentSessionLimit_FourLoginsWithMaxThree_OldestSessionEvicted()
    {
        var email = "session-limit@example.com";
        await RegisterAndActivateAsync(email);

        // Login 4 times (MaxConcurrentSessions = 3 in test server config)
        var refreshTokens = new List<string>();
        for (var i = 0; i < 4; i++)
        {
            var resp = await _client.PostAsJsonAsync(
                "/api/bedrock/auth/login",
                new LoginRequest(email, ValidPassword));
            var cookie = resp.GetRefreshCookieValue();
            cookie.Should().NotBeNullOrEmpty();
            refreshTokens.Add(cookie!);
        }

        // Only 3 sessions should be active; the first (oldest) should have been evicted
        _client.SetRefreshCookie(refreshTokens[0]);
        var firstTokenResp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
        firstTokenResp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "the oldest session should have been evicted when the 4th session was created");

        // The latest 3 tokens should still be valid
        for (var i = 1; i <= 3; i++)
        {
            _client.SetRefreshCookie(refreshTokens[i]);
            var resp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh", new RefreshRequest());
            resp.StatusCode.Should().Be(HttpStatusCode.OK,
                because: $"token {i} should still be valid (only the oldest is evicted)");
            // Consume the new token to avoid interference with subsequent iterations
            var rotated = resp.GetRefreshCookieValue();
            rotated.Should().NotBeNullOrEmpty();
            refreshTokens[i] = rotated!;
        }
        _client.SetRefreshCookie(null);
    }

    // -------------------------------------------------------------------------
    // Enrollment token scope enforcement
    // -------------------------------------------------------------------------

    [Fact]
    public async Task EnrollmentToken_OnNonEnrollmentEndpoint_Returns403()
    {
        var userId = Guid.NewGuid();

        // Generate an enrollment token directly via ITokenService
        var tokenService = _server.Host.Services.GetRequiredService<ITokenService>();
        var enrollmentToken = tokenService.GenerateEnrollmentToken(userId);

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", enrollmentToken);

        // A non-enrollment endpoint (sessions list) must reject enrollment tokens
        var resp = await _client.GetAsync("/api/bedrock/sessions");

        _client.DefaultRequestHeaders.Authorization = null;
        resp.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task RegularAccessToken_OnProtectedEndpoint_Returns200()
    {
        var email = "scope-access@example.com";
        var tokens = await RegisterActivateAndLoginAsync(email);

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var resp = await _client.GetAsync("/api/bedrock/sessions");
        _client.DefaultRequestHeaders.Authorization = null;

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // -------------------------------------------------------------------------
    // G7 — Access token blacklisted after password change
    // -------------------------------------------------------------------------

    [Fact]
    public async Task PasswordChange_PreChangeAccessToken_IsRejectedWith401()
    {
        var email = "pw-change-revoke@example.com";
        await RegisterAndActivateAsync(email);

        // Login → capture the access token issued for this session
        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        loginResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginBody = await ReadAsync<BedrockResponse<LoginResponse>>(loginResp);
        var oldAccessToken = loginBody.Data!.AccessToken!;

        // Verify the access token is valid before the password change
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", oldAccessToken);
        var beforeResp = await _client.GetAsync("/api/bedrock/sessions");
        _client.DefaultRequestHeaders.Authorization = null;
        beforeResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Change the password (triggers RevokeAllAsync which blacklists all session JTIs)
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", oldAccessToken);
        var changeResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/change-password",
            new ChangePasswordRequest(ValidPassword, "NewValidP@ssword2!"));
        _client.DefaultRequestHeaders.Authorization = null;
        changeResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // The old access token must now be rejected even though it hasn't expired
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", oldAccessToken);
        var afterResp = await _client.GetAsync("/api/bedrock/sessions");
        _client.DefaultRequestHeaders.Authorization = null;

        afterResp.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "a pre-change access token's JTI must be blacklisted after password change");
    }

    // -------------------------------------------------------------------------
    // Enumeration-safe endpoints always return 200
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Revoke_UnknownToken_Returns200()
    {
        var resp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/revoke",
            new RevokeRequest("completely-unknown-token"));

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ForgotPassword_UnknownEmail_Returns200()
    {
        var resp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/forgot-password",
            new ForgotPasswordRequest("nobody@example.com"));

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "forgot-password must never reveal whether an email is registered");
    }

    [Fact]
    public async Task ForgotPassword_KnownEmail_Returns200()
    {
        var email = "forgot-known@example.com";
        await RegisterAndActivateAsync(email);

        var resp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/forgot-password",
            new ForgotPasswordRequest(email));

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "forgot-password must return 200 for both known and unknown emails");
    }

    // -------------------------------------------------------------------------
    // Enumeration-safe token errors — expired and non-existent must be identical
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ResetPassword_ExpiredToken_SameErrorAsNonExistent()
    {
        var email = "pw-reset-enum@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;

        await _client.PostAsJsonAsync("/api/bedrock/auth/forgot-password", new ForgotPasswordRequest(email));

        var resetToken = _server.DbContext.PasswordResetTokens.First(t => t.UserId == userId);
        _server.DbContext.Entry(resetToken).Property(t => t.ExpiresAt).CurrentValue =
            DateTime.UtcNow.AddHours(-1);
        await _server.DbContext.SaveChangesAsync();

        var expiredResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/reset-password",
            new ResetPasswordRequest(resetToken.TokenHash, "NewValidP@ssword1!"));
        expiredResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var expiredBody = await ReadAsync<BedrockResponse>(expiredResp);

        var nonExistentResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/reset-password",
            new ResetPasswordRequest("0000000000000000000000000000000000000000000000000000000000000000", "NewValidP@ssword1!"));
        nonExistentResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var nonExistentBody = await ReadAsync<BedrockResponse>(nonExistentResp);

        expiredBody.Errors.Should().BeEquivalentTo(nonExistentBody.Errors,
            because: "expired and non-existent password reset tokens must return identical errors to prevent enumeration");
    }

    [Fact]
    public async Task ConfirmEmail_ExpiredToken_SameErrorAsNonExistent()
    {
        var email = "email-verify-enum@example.com";
        await _client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;

        var verifyToken = _server.DbContext.EmailVerificationTokens.First(t => t.UserId == userId);
        _server.DbContext.Entry(verifyToken).Property(t => t.ExpiresAt).CurrentValue =
            DateTime.UtcNow.AddHours(-1);
        await _server.DbContext.SaveChangesAsync();

        var expiredResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest(verifyToken.TokenHash));
        expiredResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var expiredBody = await ReadAsync<BedrockResponse>(expiredResp);

        var nonExistentResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest("0000000000000000000000000000000000000000000000000000000000000000"));
        nonExistentResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var nonExistentBody = await ReadAsync<BedrockResponse>(nonExistentResp);

        expiredBody.Errors.Should().BeEquivalentTo(nonExistentBody.Errors,
            because: "expired and non-existent email verification tokens must return identical errors to prevent enumeration");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task RegisterAndActivateAsync(string email)
    {
        await _client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);
        await _client.PostAsJsonAsync("/api/bedrock/auth/confirm-email", new ConfirmEmailRequest(rawToken));
    }

    private async Task<LoginResponse> RegisterActivateAndLoginAsync(string email)
    {
        await RegisterAndActivateAsync(email);
        var resp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var body = await ReadAsync<BedrockResponse<LoginResponse>>(resp);
        return body.Data!;
    }

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(json, JsonOptions)!;
    }

    public void Dispose() => _server.Dispose();
}
