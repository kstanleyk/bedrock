using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using Crestacle.Bedrock.Tests.Integration.Infrastructure.Postgres;
using FluentAssertions;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers.Postgres;

/// <summary>
/// G2 — PostgreSQL provider integration tests.
///
/// These tests mirror the core SQLite integration tests but run against a real PostgreSQL
/// database. They are skipped automatically when <c>BEDROCK_TEST_PG_CONNECTION</c> is not
/// set. To run them locally:
/// <code>
/// $env:BEDROCK_TEST_PG_CONNECTION = "Host=localhost;Database=bedrock_test;Username=postgres;Password=secret"
/// dotnet test --filter "Provider=Postgres"
/// </code>
/// </summary>
/// <remarks>
/// All tests in this class share the [Collection("Postgres")] group, which prevents
/// parallel execution between Postgres test classes (each class wipes and recreates the
/// schema in its constructor).
/// </remarks>
[Collection("Postgres")]
[Trait("Provider", "Postgres")]
public sealed class PostgresIntegrationTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly PostgresBedrockTestServer _server;
    private readonly HttpClient _client;

    private const string ValidPassword = "ValidP@ssword1!";

    public PostgresIntegrationTests()
    {
        _server = new PostgresBedrockTestServer();
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------------

    [PostgresFact]
    public async Task Register_ValidRequest_Returns200()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest("pg-register@example.com", ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse>(response);
        body.Success.Should().BeTrue();
    }

    [PostgresFact]
    public async Task Register_DuplicateEmail_Returns400()
    {
        const string email = "pg-dup@example.com";
        await _client.PostAsJsonAsync("/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ReadAsync<BedrockResponse>(response);
        body.Success.Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // Login
    // -------------------------------------------------------------------------

    [PostgresFact]
    public async Task Login_ValidCredentials_ReturnsTokens()
    {
        const string email = "pg-login@example.com";
        await RegisterAndActivateAsync(email);

        var tokens = await LoginAsync(email);

        tokens.AccessToken.Should().NotBeNullOrEmpty();
        tokens.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [PostgresFact]
    public async Task Login_InvalidPassword_Returns401()
    {
        const string email = "pg-badpw@example.com";
        await RegisterAndActivateAsync(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, "WrongPassword1!"));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // -------------------------------------------------------------------------
    // Refresh token rotation
    // -------------------------------------------------------------------------

    [PostgresFact]
    public async Task Refresh_ValidToken_ReturnsNewTokens()
    {
        const string email = "pg-refresh@example.com";
        await RegisterAndActivateAsync(email);
        var loginTokens = await LoginAsync(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(loginTokens.RefreshToken!));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<TokenResponse>>(response);
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();
    }

    [PostgresFact]
    public async Task Refresh_OldToken_IsRejectedAfterRotation()
    {
        const string email = "pg-rotate@example.com";
        await RegisterAndActivateAsync(email);
        var loginTokens = await LoginAsync(email);

        await _client.PostAsJsonAsync("/api/bedrock/auth/refresh",
            new RefreshRequest(loginTokens.RefreshToken!));

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(loginTokens.RefreshToken!));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "the original refresh token must be invalidated after first use");
    }

    // -------------------------------------------------------------------------
    // Concurrent session limit
    // -------------------------------------------------------------------------

    [PostgresFact]
    public async Task ConcurrentSessionLimit_FourLoginsWithMaxThree_OldestEvicted()
    {
        const string email = "pg-sessions@example.com";
        await RegisterAndActivateAsync(email);

        var refreshTokens = new List<string>();
        for (var i = 0; i < 4; i++)
        {
            var resp = await _client.PostAsJsonAsync("/api/bedrock/auth/login",
                new LoginRequest(email, ValidPassword));
            var body = await ReadAsync<BedrockResponse<LoginResponse>>(resp);
            refreshTokens.Add(body.Data!.RefreshToken!);
        }

        var firstResp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh",
            new RefreshRequest(refreshTokens[0]));
        firstResp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "the oldest session must be evicted when the 4th session is created");

        for (var i = 1; i <= 3; i++)
        {
            var resp = await _client.PostAsJsonAsync("/api/bedrock/auth/refresh",
                new RefreshRequest(refreshTokens[i]));
            resp.StatusCode.Should().Be(HttpStatusCode.OK,
                because: $"token {i} should still be valid");
            var body = await ReadAsync<BedrockResponse<TokenResponse>>(resp);
            refreshTokens[i] = body.Data!.RefreshToken!;
        }
    }

    // -------------------------------------------------------------------------
    // Audit logging
    // -------------------------------------------------------------------------

    [PostgresFact]
    public async Task Login_AuditEventRecorded()
    {
        const string email = "pg-audit@example.com";
        await RegisterAndActivateAsync(email);
        var tokens = await LoginAsync(email);

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var response = await _client.GetAsync("/api/bedrock/audit");
        _client.DefaultRequestHeaders.Authorization = null;

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<AuditQueryResponse>>(response);
        body.Data!.Items.Should().NotBeEmpty(because: "login must produce at least one audit entry");
        body.Data.TotalCount.Should().BeGreaterThan(0);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task RegisterAndActivateAsync(string email)
    {
        await _client.PostAsJsonAsync("/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        var tokenHash = _server.DbContext.EmailVerificationTokens
            .First(t => t.UserId == userId).TokenHash;

        await _client.PostAsJsonAsync("/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest(tokenHash));
    }

    private async Task<LoginResponse> LoginAsync(string email)
    {
        var resp = await _client.PostAsJsonAsync("/api/bedrock/auth/login",
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
