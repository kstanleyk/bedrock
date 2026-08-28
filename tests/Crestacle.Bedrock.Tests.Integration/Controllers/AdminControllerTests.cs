using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

/// <summary>F6 — Admin management API integration tests.</summary>
public sealed class AdminControllerTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;

    private const string ValidPassword = "ValidP@ssword1!";

    public AdminControllerTests()
    {
        _server = new BedrockTestServer(
            configureServices: s => s.AddSingleton<IBedrockClaimsEnricher, AdminClaimsEnricher>());
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // GET /admin/users
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetUsers_WithAdminToken_Returns200WithPagedResult()
    {
        var email = "admin-list@example.com";
        await RegisterAndActivateAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.GetAsync("/api/bedrock/admin/users");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<PagedResult<CredentialSummary>>(response);
        body.Data.Should().NotBeNull();
        body.Data!.Items.Should().NotBeEmpty();
        body.Data!.TotalCount.Should().BeGreaterThan(0);

        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // GET /admin/users/{userId}
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetUser_WithAdminToken_Returns200WithDetail()
    {
        var email = "admin-detail@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.GetAsync($"/api/bedrock/admin/users/{userId}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<CredentialDetail>(response);
        body.Data.Should().NotBeNull();
        body.Data!.UserId.Should().Be(userId);
        body.Data!.Email.Should().Be(email);
        body.Data!.EmailConfirmed.Should().BeTrue();

        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task GetUser_UnknownUserId_Returns404()
    {
        var email = "admin-detail-notfound@example.com";
        await RegisterAndActivateAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.GetAsync($"/api/bedrock/admin/users/{Guid.NewGuid()}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // POST /admin/users/{userId}/lock
    // -------------------------------------------------------------------------

    [Fact]
    public async Task LockUser_WithAdminToken_UserIsLockedOut()
    {
        var email = "admin-lock@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var lockResponse = await _client.PostAsync($"/api/bedrock/admin/users/{userId}/lock", null);
        lockResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var detailResponse = await _client.GetAsync($"/api/bedrock/admin/users/{userId}");
        var detail = (await ReadBedrockResponseAsync<CredentialDetail>(detailResponse)).Data!;
        detail.IsLockedOut.Should().BeTrue();

        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // POST /admin/users/{userId}/unlock
    // -------------------------------------------------------------------------

    [Fact]
    public async Task UnlockUser_WithAdminToken_UserIsNoLongerLockedOut()
    {
        var email = "admin-unlock@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        await _client.PostAsync($"/api/bedrock/admin/users/{userId}/lock", null);

        var unlockResponse = await _client.PostAsync($"/api/bedrock/admin/users/{userId}/unlock", null);
        unlockResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var detailResponse = await _client.GetAsync($"/api/bedrock/admin/users/{userId}");
        var detail = (await ReadBedrockResponseAsync<CredentialDetail>(detailResponse)).Data!;
        detail.IsLockedOut.Should().BeFalse();

        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // POST /admin/users/{userId}/reset-mfa
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ResetMfa_WithAdminToken_Returns200()
    {
        var email = "admin-resetmfa@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.PostAsync($"/api/bedrock/admin/users/{userId}/reset-mfa", null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // POST /admin/users/{userId}/expire-password
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ExpirePassword_WithAdminToken_PasswordExpiresAtIsInPast()
    {
        var email = "admin-expirepwd@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var expireResponse = await _client.PostAsync($"/api/bedrock/admin/users/{userId}/expire-password", null);
        expireResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var detailResponse = await _client.GetAsync($"/api/bedrock/admin/users/{userId}");
        var detail = (await ReadBedrockResponseAsync<CredentialDetail>(detailResponse)).Data!;
        detail.PasswordExpiresAt.Should().NotBeNull();
        detail.PasswordExpiresAt!.Value.Should().BeBefore(DateTime.UtcNow.AddSeconds(1));

        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // DELETE /admin/users/{userId}/sessions
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAllSessions_WithAdminToken_Returns200()
    {
        var email = "admin-revokesessions@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.DeleteAsync($"/api/bedrock/admin/users/{userId}/sessions");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // POST /admin/users/{userId}/change-email
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ChangeEmail_WithAdminToken_UpdatesEmailAndRevokesSessions()
    {
        var email = "admin-changeemail@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        const string newEmail = "admin-changeemail-new@example.com";
        var response = await _client.PostAsJsonAsync(
            $"/api/bedrock/admin/users/{userId}/change-email", new AdminChangeEmailRequest(newEmail));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Changing your own email revokes all sessions (same as ResetPassword), so the token
        // above is now blocklisted - re-authenticate with the new address to confirm both the
        // persisted change and that login now works with it.
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(newEmail));

        var detailResponse = await _client.GetAsync($"/api/bedrock/admin/users/{userId}");
        var detail = (await ReadBedrockResponseAsync<CredentialDetail>(detailResponse)).Data!;
        detail.Email.Should().Be(newEmail);

        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task ChangeEmail_SameEmail_IsNoOpAnd200()
    {
        var email = "admin-changeemail-noop@example.com";
        await RegisterAndActivateAsync(email);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.PostAsJsonAsync(
            $"/api/bedrock/admin/users/{userId}/change-email", new AdminChangeEmailRequest(email));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task ChangeEmail_AddressAlreadyInUse_Returns401()
    {
        var email = "admin-changeemail-dup1@example.com";
        var otherEmail = "admin-changeemail-dup2@example.com";
        await RegisterAndActivateAsync(email);
        await RegisterAndActivateAsync(otherEmail);
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.PostAsJsonAsync(
            $"/api/bedrock/admin/users/{userId}/change-email", new AdminChangeEmailRequest(otherEmail));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task ChangeEmail_UnknownUserId_Returns404()
    {
        var email = "admin-changeemail-notfound@example.com";
        await RegisterAndActivateAsync(email);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await GetAdminTokenAsync(email));

        var response = await _client.PostAsJsonAsync(
            $"/api/bedrock/admin/users/{Guid.NewGuid()}/change-email",
            new AdminChangeEmailRequest("nobody@example.com"));

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    // -------------------------------------------------------------------------
    // Authorization — non-admin tokens are rejected with 403
    // -------------------------------------------------------------------------

    [Fact]
    public async Task AdminEndpoints_WithoutAdminClaim_Return403()
    {
        using var plainServer = new BedrockTestServer();
        using var plainClient = plainServer.Client;

        var email = "admin-noadmin@example.com";
        await RegisterAndActivateAsync(email, plainClient, plainServer);

        var loginResponse = await plainClient.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var loginBody = await ReadBedrockResponseAsync<LoginResponse>(loginResponse);
        var regularToken = loginBody.Data!.AccessToken!;

        plainClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", regularToken);

        var userId = plainServer.DbContext.UserCredentials.First(c => c.Email == email).UserId;

        (await plainClient.GetAsync("/api/bedrock/admin/users"))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await plainClient.GetAsync($"/api/bedrock/admin/users/{userId}"))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await plainClient.PostAsync($"/api/bedrock/admin/users/{userId}/lock", null))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task RegisterAndActivateAsync(string email)
        => await RegisterAndActivateAsync(email, _client, _server);

    private static async Task RegisterAndActivateAsync(
        string email, HttpClient client, BedrockTestServer server)
    {
        await client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));

        var userId = server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        var tokenHash = server.DbContext.EmailVerificationTokens.First(t => t.UserId == userId).TokenHash;

        await client.PostAsJsonAsync("/api/bedrock/auth/confirm-email", new ConfirmEmailRequest(tokenHash));
    }

    private async Task<string> GetAdminTokenAsync(string email)
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        return body.Data!.AccessToken!;
    }

    private static async Task<BedrockResponse<T>> ReadBedrockResponseAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<BedrockResponse<T>>(json, JsonOptions)!;
    }

    public void Dispose() => _server.Dispose();

    private sealed class AdminClaimsEnricher : IBedrockClaimsEnricher
    {
        public Task<IDictionary<string, string>> EnrichAsync(Guid userId, CancellationToken ct = default)
            => Task.FromResult<IDictionary<string, string>>(
                new Dictionary<string, string> { ["bedrock_admin"] = "true" });
    }
}
