using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
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

        // Login → get access + refresh tokens
        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        loginResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginBody = await ReadAsync<BedrockResponse<LoginResponse>>(loginResp);
        loginBody.Data!.AccessToken.Should().NotBeNullOrEmpty();
        loginBody.Data.RefreshToken.Should().NotBeNullOrEmpty();
        var refresh1 = loginBody.Data.RefreshToken!;

        // Use access token to access a protected endpoint
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", loginBody.Data.AccessToken);
        var sessions = await _client.GetAsync("/api/bedrock/sessions");
        sessions.StatusCode.Should().Be(HttpStatusCode.OK);
        _client.DefaultRequestHeaders.Authorization = null;

        // Refresh → get new token pair
        var refreshResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(refresh1));
        refreshResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var refreshBody = await ReadAsync<BedrockResponse<TokenResponse>>(refreshResp);
        refreshBody.Data!.AccessToken.Should().NotBeNullOrEmpty();
        var refresh2 = refreshBody.Data.RefreshToken;

        // Old refresh token must be rejected (rotated)
        var oldRefreshResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(refresh1));
        oldRefreshResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // Revoke the new token
        var revokeResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/revoke",
            new RevokeRequest(refresh2));
        revokeResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Revoked token must be rejected
        var revokedRefreshResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(refresh2));
        revokedRefreshResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // Refresh token rotation chain
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RefreshRotationChain_ThreeRotations_EachGeneratesUniqueToken()
    {
        var email = "rotation-chain@example.com";
        var initialTokens = await RegisterActivateAndLoginAsync(email);

        var tokens = new List<string> { initialTokens.RefreshToken! };

        // Rotate 3 times; each must succeed and produce a distinct refresh token
        for (var i = 0; i < 3; i++)
        {
            var resp = await _client.PostAsJsonAsync(
                "/api/bedrock/auth/refresh",
                new RefreshRequest(tokens[^1]));
            resp.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await ReadAsync<BedrockResponse<TokenResponse>>(resp);
            body.Data!.RefreshToken.Should().NotBeNullOrEmpty();
            tokens.Add(body.Data.RefreshToken);
        }

        tokens.Should().OnlyHaveUniqueItems();

        // All previous tokens must be rejected
        foreach (var stale in tokens.SkipLast(1))
        {
            var reject = await _client.PostAsJsonAsync(
                "/api/bedrock/auth/refresh",
                new RefreshRequest(stale));
            reject.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
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
            var body = await ReadAsync<BedrockResponse<LoginResponse>>(resp);
            refreshTokens.Add(body.Data!.RefreshToken!);
        }

        // Only 3 sessions should be active; the first (oldest) should have been evicted
        var firstTokenResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(refreshTokens[0]));
        firstTokenResp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "the oldest session should have been evicted when the 4th session was created");

        // The latest 3 tokens should still be valid
        for (var i = 1; i <= 3; i++)
        {
            var resp = await _client.PostAsJsonAsync(
                "/api/bedrock/auth/refresh",
                new RefreshRequest(refreshTokens[i]));
            resp.StatusCode.Should().Be(HttpStatusCode.OK,
                because: $"token {i} should still be valid (only the oldest is evicted)");
            // Consume the new token to avoid interference with subsequent iterations
            var body = await ReadAsync<BedrockResponse<TokenResponse>>(resp);
            refreshTokens[i] = body.Data!.RefreshToken;
        }
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
