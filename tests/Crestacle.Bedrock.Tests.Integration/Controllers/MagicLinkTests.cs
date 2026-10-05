using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

public sealed class MagicLinkTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";

    public MagicLinkTests()
    {
        _server = new BedrockTestServer(
            configureServices: services => services.AddSingleton<IEmailSender>(_emailSender));
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/magic-link — request
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RequestMagicLink_KnownEmail_Returns200()
    {
        const string email = "ml-request-known@example.com";
        await RegisterAndActivateAsync(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync(response);
        body.Success.Should().BeTrue();
    }

    [Fact]
    public async Task RequestMagicLink_UnknownEmail_StillReturns200()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest("nobody-ml@example.com"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RequestMagicLink_UnconfirmedEmail_StillReturns200()
    {
        const string email = "ml-unconfirmed@example.com";
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Confirm no token was created — account was not active (unconfirmed)
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _server.DbContext.MagicLinkTokens.Any(t => t.UserId == userId).Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/magic-link/verify — happy path
    // -------------------------------------------------------------------------

    [Fact]
    public async Task VerifyMagicLink_ValidToken_ReturnsTokens()
    {
        const string email = "ml-verify-ok@example.com";
        await RegisterAndActivateAsync(email);
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        var rawToken = GetMagicLinkRawToken(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest(rawToken));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        body.Success.Should().BeTrue();
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();
        body.Data.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task VerifyMagicLink_TokenIsMarkedUsedAfterConsumption()
    {
        const string email = "ml-used@example.com";
        await RegisterAndActivateAsync(email);
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        // The stored hash (for the post-consumption DB lookup) and the raw token the user
        // actually received (for the request body) are different values — capture both.
        var tokenHash = GetMagicLinkTokenHash(email);
        var rawToken = GetMagicLinkRawToken(email);
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest(rawToken));

        _server.DbContext.ChangeTracker.Clear();
        var token = _server.DbContext.MagicLinkTokens.First(t => t.TokenHash == tokenHash);
        token.UsedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task VerifyMagicLink_TokenCannotBeReused()
    {
        const string email = "ml-reuse@example.com";
        await RegisterAndActivateAsync(email);
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        var rawToken = GetMagicLinkRawToken(email);

        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest(rawToken));

        var secondResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest(rawToken));

        secondResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/magic-link/verify — error cases
    // -------------------------------------------------------------------------

    [Fact]
    public async Task VerifyMagicLink_InvalidToken_Returns401()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest("invalid-token-hash"));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task VerifyMagicLink_NewRequestInvalidatesPreviousToken()
    {
        const string email = "ml-invalidate@example.com";
        await RegisterAndActivateAsync(email);

        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));
        var firstRawToken = GetMagicLinkRawToken(email);

        // Second request should invalidate the first token
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        var firstTokenResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest(firstRawToken));

        firstTokenResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // -------------------------------------------------------------------------
    // MFA gate — magic link must not bypass enrolled MFA
    // -------------------------------------------------------------------------

    [Fact]
    public async Task VerifyMagicLink_MfaEnabled_ReturnsChallengeNotTokens()
    {
        const string email = "ml-mfa@example.com";
        await RegisterAndActivateAsync(email);

        // Enable EmailOtp MFA directly on the credential (same pattern as other controller tests)
        var credential = _server.DbContext.UserCredentials.First(c => c.Email == email);
        credential.EnableMfa(Core.Enumerations.MfaMethod.EmailOtp);
        await _server.DbContext.SaveChangesAsync();
        _server.DbContext.ChangeTracker.Clear();

        // Request and verify magic link
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        var rawToken = GetMagicLinkRawToken(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest(rawToken));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        body.Success.Should().BeTrue();
        body.Data!.RequiresMfa.Should().BeTrue();
        body.Data.ChallengeToken.Should().NotBeNullOrEmpty();
        body.Data.AccessToken.Should().BeNull();
    }

    // -------------------------------------------------------------------------
    // Audit log
    // -------------------------------------------------------------------------

    [Fact]
    public async Task VerifyMagicLink_WritesAuditEntries()
    {
        const string email = "ml-audit@example.com";
        await RegisterAndActivateAsync(email);

        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link",
            new MagicLinkRequest(email));

        var rawToken = GetMagicLinkRawToken(email);

        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/magic-link/verify",
            new VerifyMagicLinkRequest(rawToken));

        _server.DbContext.ChangeTracker.Clear();
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        var auditTypes = _server.DbContext.AuditEntries
            .Where(a => a.UserId == userId)
            .Select(a => a.EventType)
            .ToList();

        auditTypes.Should().Contain(Core.Enumerations.AuditEventType.MagicLinkRequested);
        auditTypes.Should().Contain(Core.Enumerations.AuditEventType.MagicLinkConsumed);
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

    // The real raw token a user would receive by email — for the verify request body.
    private string GetMagicLinkRawToken(string email)
        => CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);

    private async Task<LoginResponse> LoginAsync(string email)
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        return body.Data!;
    }

    private string GetMagicLinkTokenHash(string email)
    {
        _server.DbContext.ChangeTracker.Clear();
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        return _server.DbContext.MagicLinkTokens
            .Where(t => t.UserId == userId && t.UsedAt == null)
            .OrderByDescending(t => t.CreatedAt)
            .First()
            .TokenHash;
    }

    private static async Task<BedrockResponse> ReadBedrockResponseAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<BedrockResponse>(json, JsonOptions)!;
    }

    private static async Task<BedrockResponse<T>> ReadBedrockResponseAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<BedrockResponse<T>>(json, JsonOptions)!;
    }

    public void Dispose() => _server.Dispose();
}
