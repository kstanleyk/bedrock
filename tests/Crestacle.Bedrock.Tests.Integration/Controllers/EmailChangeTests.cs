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

public sealed class EmailChangeTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";

    public EmailChangeTests()
    {
        _server = new BedrockTestServer(
            configureServices: services => services.AddSingleton<IEmailSender>(_emailSender));
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/account/request-email-change
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RequestEmailChange_ThenConfirm_UpdatesEmailAndRevokesOldSession()
    {
        const string oldEmail = "email-change-from@example.com";
        const string newEmail = "email-change-to@example.com";

        await RegisterAndActivateAsync(oldEmail);
        var tokens = await LoginAsync(oldEmail);

        _client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        // Request the email change
        var requestResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/account/request-email-change",
            new RequestEmailChangeRequest(newEmail));
        requestResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var userId = _server.DbContext.UserCredentials.First(c => c.Email == oldEmail).UserId;

        // The real raw token a user would receive at the new address (not the stored hash).
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(newEmail)!);

        _client.DefaultRequestHeaders.Authorization = null;

        // Confirm the email change (anonymous)
        var confirmResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email-change",
            new ConfirmEmailChangeRequest(rawToken));
        confirmResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Assert credential email is updated
        _server.DbContext.ChangeTracker.Clear();
        var updated = _server.DbContext.UserCredentials.First(c => c.UserId == userId);
        updated.Email.Should().Be(newEmail);

        // Assert old refresh token is revoked — refresh should now fail
        var refreshResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(tokens.RefreshToken!));
        refreshResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task RequestEmailChange_NewEmailAlreadyTaken_Returns400()
    {
        const string existingEmail = "existing-taken@example.com";
        const string requesterEmail = "requester-email-change@example.com";

        await RegisterAndActivateAsync(existingEmail);
        await RegisterAndActivateAsync(requesterEmail);
        var tokens = await LoginAsync(requesterEmail);

        _client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/account/request-email-change",
            new RequestEmailChangeRequest(existingEmail));
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task RequestEmailChange_Unauthenticated_Returns401()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/account/request-email-change",
            new RequestEmailChangeRequest("any@example.com"));
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ConfirmEmailChange_InvalidToken_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email-change",
            new ConfirmEmailChangeRequest("notarealhash"));
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
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

    private async Task<LoginResponse> LoginAsync(string email)
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));

        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        return body.Data!;
    }

    private static async Task<BedrockResponse<T>> ReadBedrockResponseAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<BedrockResponse<T>>(json, JsonOptions)!;
    }

    public void Dispose() => _server.Dispose();
}
