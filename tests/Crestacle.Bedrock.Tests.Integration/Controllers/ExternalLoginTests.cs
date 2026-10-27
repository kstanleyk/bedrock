using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

public sealed class ExternalLoginTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private const string ValidPassword = "ValidP@ssword1!";
    private const string FakeProvider = "fake";

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    public ExternalLoginTests()
    {
        _server = new BedrockTestServer(
            configureServices: services =>
            {
                services.AddScoped<IExternalIdentityValidator, FakeExternalIdentityValidator>();
                services.AddSingleton<IEmailSender>(_emailSender);
            });
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/external-login — happy path
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ExternalLogin_LinkedIdentity_ReturnsTokens()
    {
        const string email = "ext-login-ok@example.com";
        var userId = await RegisterAndActivateAsync(email);

        // Link the external identity first
        var accessToken = await LoginAndGetTokenAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        await _client.PostAsJsonAsync(
            "/api/bedrock/account/link-external",
            new LinkExternalIdentityRequest(FakeProvider, "token-abc"));

        _client.DefaultRequestHeaders.Authorization = null;

        // Now do external login
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/external-login",
            new ExternalLoginRequest(FakeProvider, "token-abc"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        body.Success.Should().BeTrue();
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();
        body.Data.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ExternalLogin_AutoLinkViaEmail_ReturnsTokens()
    {
        const string email = "ext-autolink@example.com";
        await RegisterAndActivateAsync(email);

        // Token contains email claim (FakeValidator treats "email:<email>" as email)
        var providerToken = $"email:{email}";

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/external-login",
            new ExternalLoginRequest(FakeProvider, providerToken));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        body.Success.Should().BeTrue();
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();

        // ExternalIdentity should now be in the database
        _server.DbContext.ChangeTracker.Clear();
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _server.DbContext.ExternalIdentities
            .Any(e => e.UserId == userId && e.Provider == FakeProvider)
            .Should().BeTrue();
    }

    [Fact]
    public async Task ExternalLogin_NoLinkedAccount_Returns404()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/external-login",
            new ExternalLoginRequest(FakeProvider, "unknown-user-token"));

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task ExternalLogin_UnknownProvider_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/external-login",
            new ExternalLoginRequest("nonexistent-provider", "some-token"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ExternalLogin_WritesAuditEntry()
    {
        const string email = "ext-audit@example.com";
        await RegisterAndActivateAsync(email);

        var providerToken = $"email:{email}";
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/external-login",
            new ExternalLoginRequest(FakeProvider, providerToken));

        _server.DbContext.ChangeTracker.Clear();
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _server.DbContext.AuditEntries
            .Any(a => a.UserId == userId && a.EventType == AuditEventType.ExternalLoginSucceeded)
            .Should().BeTrue();
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/account/link-external
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Link_ValidToken_LinksIdentityAndAudits()
    {
        const string email = "ext-link@example.com";
        await RegisterAndActivateAsync(email);
        var accessToken = await LoginAndGetTokenAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/account/link-external",
            new LinkExternalIdentityRequest(FakeProvider, "unique-link-token"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        _server.DbContext.ChangeTracker.Clear();
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _server.DbContext.ExternalIdentities
            .Any(e => e.UserId == userId && e.Provider == FakeProvider)
            .Should().BeTrue();
        _server.DbContext.AuditEntries
            .Any(a => a.UserId == userId && a.EventType == AuditEventType.ExternalIdentityLinked)
            .Should().BeTrue();
    }

    [Fact]
    public async Task Link_Unauthenticated_Returns401()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/account/link-external",
            new LinkExternalIdentityRequest(FakeProvider, "token"));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Link_AlreadyLinked_Returns400()
    {
        const string email = "ext-link-dup@example.com";
        await RegisterAndActivateAsync(email);
        var accessToken = await LoginAndGetTokenAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        const string providerToken = "dup-link-token";
        await _client.PostAsJsonAsync(
            "/api/bedrock/account/link-external",
            new LinkExternalIdentityRequest(FakeProvider, providerToken));

        var secondResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/account/link-external",
            new LinkExternalIdentityRequest(FakeProvider, providerToken));

        secondResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // DELETE /api/bedrock/account/external/{provider}
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Unlink_HasPassword_Returns200()
    {
        const string email = "ext-unlink@example.com";
        await RegisterAndActivateAsync(email);
        var accessToken = await LoginAndGetTokenAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        await _client.PostAsJsonAsync(
            "/api/bedrock/account/link-external",
            new LinkExternalIdentityRequest(FakeProvider, "unlink-token"));

        var response = await _client.DeleteAsync(
            $"/api/bedrock/account/external/{FakeProvider}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        _server.DbContext.ChangeTracker.Clear();
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _server.DbContext.ExternalIdentities
            .Any(e => e.UserId == userId && e.Provider == FakeProvider)
            .Should().BeFalse();
        _server.DbContext.AuditEntries
            .Any(a => a.UserId == userId && a.EventType == AuditEventType.ExternalIdentityUnlinked)
            .Should().BeTrue();
    }

    [Fact]
    public async Task Unlink_NotLinked_Returns404()
    {
        const string email = "ext-unlink-notfound@example.com";
        await RegisterAndActivateAsync(email);
        var accessToken = await LoginAndGetTokenAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await _client.DeleteAsync(
            $"/api/bedrock/account/external/{FakeProvider}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // -------------------------------------------------------------------------
    // Full flow: register → link → external login
    // -------------------------------------------------------------------------

    [Fact]
    public async Task FullFlow_RegisterLinkExternalLogin_IssuesTokens()
    {
        const string email = "ext-fullflow@example.com";
        await RegisterAndActivateAsync(email);

        // Link
        var accessToken = await LoginAndGetTokenAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        await _client.PostAsJsonAsync(
            "/api/bedrock/account/link-external",
            new LinkExternalIdentityRequest(FakeProvider, "ff-token"));

        _client.DefaultRequestHeaders.Authorization = null;

        // External login
        var loginResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/external-login",
            new ExternalLoginRequest(FakeProvider, "ff-token"));

        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<LoginResponse>(loginResponse);
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();
        body.Data.RefreshToken.Should().NotBeNullOrEmpty();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task<Guid> RegisterAndActivateAsync(string email)
    {
        await _client.PostAsJsonAsync("/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);

        await _client.PostAsJsonAsync("/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest(rawToken));

        return _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
    }

    private async Task<string> LoginAndGetTokenAsync(string email)
    {
        var response = await _client.PostAsJsonAsync("/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));

        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        return body.Data!.AccessToken!;
    }

    private static async Task<BedrockResponse<T>> ReadBedrockResponseAsync<T>(
        HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<BedrockResponse<T>>(json, JsonOptions)!;
    }

    public void Dispose()
    {
        _client.DefaultRequestHeaders.Authorization = null;
        _server.Dispose();
    }
}
