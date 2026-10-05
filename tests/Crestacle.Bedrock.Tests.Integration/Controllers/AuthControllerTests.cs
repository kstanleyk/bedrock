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

public sealed class AuthControllerTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";

    public AuthControllerTests()
    {
        _server = new BedrockTestServer(
            configureServices: services => services.AddSingleton<IEmailSender>(_emailSender));
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/register
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Register_ValidRequest_Returns200()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest("ctrl-register@example.com", ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync(response);
        body.Success.Should().BeTrue();
    }

    [Fact]
    public async Task Register_DuplicateEmail_Returns400()
    {
        var email = "ctrl-dup@example.com";
        await _client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ReadBedrockResponseAsync(response);
        body.Success.Should().BeFalse();
        body.Errors.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Register_WeakPassword_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest("ctrl-weak@example.com", "short"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/confirm-email
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ConfirmEmail_ValidToken_Returns200()
    {
        var email = "ctrl-confirm@example.com";
        await _client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));

        // The real raw token a user would receive by email (not the stored hash).
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest(rawToken));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ConfirmEmail_InvalidToken_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest("invalid-token-hash"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/login
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Login_ValidCredentials_ReturnsTokens()
    {
        var email = "ctrl-login@example.com";
        await RegisterAndActivateAsync(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<LoginResponse>(response);
        body.Success.Should().BeTrue();
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();
        body.Data.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Login_InvalidPassword_Returns401()
    {
        var email = "ctrl-badpw@example.com";
        await RegisterAndActivateAsync(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, "WrongPassword1!"));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Login_UnknownEmail_Returns401()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest("nobody@example.com", ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/refresh
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Refresh_ValidToken_ReturnsNewTokens()
    {
        var email = "ctrl-refresh@example.com";
        await RegisterAndActivateAsync(email);
        var tokens = await LoginAsync(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(tokens.RefreshToken!));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<TokenResponse>(response);
        body.Success.Should().BeTrue();
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Refresh_InvalidToken_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest("not-a-valid-refresh-token"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/revoke
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Revoke_AuthenticatedUser_Returns200()
    {
        var email = "ctrl-revoke@example.com";
        await RegisterAndActivateAsync(email);
        var tokens = await LoginAsync(email);

        _client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/revoke",
            new RevokeRequest(tokens.RefreshToken!));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task Revoke_Unauthenticated_Returns200()
    {
        // Revoke is anonymous — service handles unknown/invalid tokens gracefully, always returns OK
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/revoke",
            new RevokeRequest("some-unknown-token"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
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
