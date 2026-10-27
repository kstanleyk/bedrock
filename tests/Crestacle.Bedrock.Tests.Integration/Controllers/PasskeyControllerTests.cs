using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using Fido2NetLib;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

public sealed class PasskeyControllerTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);
    private const string ValidPassword = "ValidP@ssword1!";

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    public PasskeyControllerTests()
    {
        _server = new BedrockTestServer(
            configureServices: s =>
            {
                s.AddSingleton<IFido2, FakeFido2>();
                s.AddSingleton<IEmailSender>(_emailSender);
            });
        _client = _server.Client;
    }

    public void Dispose() => _server.Dispose();

    // -------------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------------

    [Fact]
    public async Task BeginRegistration_Unauthenticated_Returns401()
    {
        var response = await _client.PostAsync(
            "/api/bedrock/passkeys/register/begin", null);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BeginRegistration_Authenticated_ReturnsOptionsJson()
    {
        var token = await RegisterActivateAndLoginAsync("pk-begin@example.com");
        UseBearer(token);

        var response = await _client.PostAsync(
            "/api/bedrock/passkeys/register/begin", null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<JsonElement>(response);
        body.Data.ValueKind.Should().Be(JsonValueKind.Object);
    }

    [Fact]
    public async Task CompleteRegistration_StoresPasskeyAndReturns200()
    {
        var token = await RegisterActivateAndLoginAsync("pk-reg@example.com");
        UseBearer(token);

        // Begin — caches the options
        await _client.PostAsync("/api/bedrock/passkeys/register/begin", null);

        // Complete with a fake attestation response
        var completeResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/passkeys/register/complete",
            new CompletePasskeyRegistrationRequest(
                FakeFido2.BuildFakeAttestationResponseJson(), "My Key"));

        completeResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Passkey should now be listed
        var listResponse = await _client.GetAsync("/api/bedrock/passkeys");
        listResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var list = await ReadAsync<IReadOnlyList<PasskeyInfoResponse>>(listResponse);
        list.Data.Should().HaveCount(1);
        list.Data![0].FriendlyName.Should().Be("My Key");
    }

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    [Fact]
    public async Task BeginAuthentication_Anonymous_ReturnsOptionsJson()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/passkeys/authenticate/begin",
            new BeginPasskeyAuthenticationRequest(null));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<JsonElement>(response);
        body.Data.ValueKind.Should().Be(JsonValueKind.Object);
    }

    [Fact]
    public async Task CompleteAuthentication_RegisterThenAuthenticate_ReturnsAccessToken()
    {
        var email = "pk-auth@example.com";
        var token = await RegisterActivateAndLoginAsync(email);
        UseBearer(token);

        // Register a passkey
        await _client.PostAsync("/api/bedrock/passkeys/register/begin", null);
        await _client.PostAsJsonAsync(
            "/api/bedrock/passkeys/register/complete",
            new CompletePasskeyRegistrationRequest(
                FakeFido2.BuildFakeAttestationResponseJson(), null));

        ClearBearer();

        // Authenticate with passkey (no Bearer needed)
        await _client.PostAsJsonAsync(
            "/api/bedrock/passkeys/authenticate/begin",
            new BeginPasskeyAuthenticationRequest(email));

        var authResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/passkeys/authenticate/complete",
            new CompletePasskeyAuthenticationRequest(
                FakeFido2.BuildFakeAssertionResponseJson()));

        authResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<LoginResponse>(authResponse);
        body.Data!.AccessToken.Should().NotBeNullOrEmpty();
        body.Data.RefreshToken.Should().NotBeNullOrEmpty();
    }

    // -------------------------------------------------------------------------
    // Credential management
    // -------------------------------------------------------------------------

    [Fact]
    public async Task DeletePasskey_Success_Removes()
    {
        var email = "pk-delete@example.com";
        var token = await RegisterActivateAndLoginAsync(email);
        UseBearer(token);

        await _client.PostAsync("/api/bedrock/passkeys/register/begin", null);
        await _client.PostAsJsonAsync(
            "/api/bedrock/passkeys/register/complete",
            new CompletePasskeyRegistrationRequest(
                FakeFido2.BuildFakeAttestationResponseJson(), null));

        var list = await ReadAsync<IReadOnlyList<PasskeyInfoResponse>>(
            await _client.GetAsync("/api/bedrock/passkeys"));
        var passkeyId = list.Data![0].Id;

        var deleteResponse = await _client.DeleteAsync($"/api/bedrock/passkeys/{passkeyId}");
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var afterDelete = await ReadAsync<IReadOnlyList<PasskeyInfoResponse>>(
            await _client.GetAsync("/api/bedrock/passkeys"));
        afterDelete.Data.Should().BeEmpty();
    }

    [Fact]
    public async Task DeletePasskey_WrongOwner_Returns400()
    {
        // Register passkey under user A
        var tokenA = await RegisterActivateAndLoginAsync("pk-owner-a@example.com");
        UseBearer(tokenA);

        await _client.PostAsync("/api/bedrock/passkeys/register/begin", null);
        await _client.PostAsJsonAsync(
            "/api/bedrock/passkeys/register/complete",
            new CompletePasskeyRegistrationRequest(
                FakeFido2.BuildFakeAttestationResponseJson(), null));

        var listA = await ReadAsync<IReadOnlyList<PasskeyInfoResponse>>(
            await _client.GetAsync("/api/bedrock/passkeys"));
        var passkeyId = listA.Data![0].Id;

        // Try to delete as user B
        var tokenB = await RegisterActivateAndLoginAsync("pk-owner-b@example.com");
        UseBearer(tokenB);

        var deleteResponse = await _client.DeleteAsync($"/api/bedrock/passkeys/{passkeyId}");
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task<string> RegisterActivateAndLoginAsync(string email)
    {
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);
        await _client.PostAsJsonAsync("/api/bedrock/auth/confirm-email", new ConfirmEmailRequest(rawToken));

        var loginResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var loginBody = await ReadAsync<LoginResponse>(loginResponse);
        return loginBody.Data!.AccessToken!;
    }

    private void UseBearer(string token)
        => _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

    private void ClearBearer()
        => _client.DefaultRequestHeaders.Authorization = null;

    private static async Task<BedrockResponse<T>> ReadAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<BedrockResponse<T>>(json, JsonOpts)!;
    }
}
