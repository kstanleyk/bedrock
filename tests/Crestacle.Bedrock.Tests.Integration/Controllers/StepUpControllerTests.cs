using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

public sealed class StepUpControllerTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;

    private const string ValidPassword = "ValidP@ssword1!";

    public StepUpControllerTests()
    {
        _server = new BedrockTestServer(
            configureServices: s => s.AddScoped<IOtpService, FakeOtpService>());
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/step-up/initiate
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Initiate_WithoutAuth_Returns401()
    {
        var response = await _client.PostAsync("/api/bedrock/step-up/initiate", null);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Initiate_MfaNotEnabled_Returns400()
    {
        var email = "stepup-nomfa@example.com";
        await RegisterAndActivateAsync(email);
        var tokens = await LoginNoMfaAsync(email);
        SetBearer(tokens.AccessToken);

        var response = await _client.PostAsync("/api/bedrock/step-up/initiate", null);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Initiate_MfaEnabled_Returns200WithChallengeId()
    {
        var email = "stepup-init@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var response = await _client.PostAsync("/api/bedrock/step-up/initiate", null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<StepUpInitiateResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.ChallengeId.Should().NotBeEmpty();
        body.Data.Method.Should().Be(MfaMethod.EmailOtp);
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/step-up/verify
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Verify_ValidChallenge_Returns200WithStepUpToken()
    {
        var email = "stepup-verify@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var challengeId = await InitiateStepUpAsync();

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/step-up/verify",
            new VerifyStepUpRequest(challengeId, FakeOtpService.FixedCode));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<StepUpVerifyResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.StepUpToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Verify_WrongCode_Returns400()
    {
        var email = "stepup-badcode@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var challengeId = await InitiateStepUpAsync();

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/step-up/verify",
            new VerifyStepUpRequest(challengeId, "000000"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Verify_UnknownChallengeId_Returns400()
    {
        var email = "stepup-badchallenge@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/step-up/verify",
            new VerifyStepUpRequest(Guid.NewGuid(), FakeOtpService.FixedCode));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // BedrockPolicyNames.Default must reject short-lived token types replayed as a
    // normal bearer token — a captured MFA-challenge or step-up token must never grant
    // access to a standard business endpoint the way a real access token does.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CapturedMfaChallengeToken_ReplayedAsBearerToken_Returns403OnDefaultPolicyEndpoint()
    {
        var email = "stepup-challenge-replay@example.com";
        await RegisterAndActivateAsync(email);

        var credential = _server.DbContext.UserCredentials.First(c => c.Email == email);
        credential.EnableMfa(MfaMethod.EmailOtp);
        await _server.DbContext.SaveChangesAsync();

        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var loginBody = await ReadAsync<BedrockResponse<LoginResponse>>(loginResp);
        var challengeToken = loginBody.Data!.ChallengeToken!;

        // The challenge token is only ever meant to be exchanged via POST /auth/verify-2fa's
        // request body (an [AllowAnonymous] endpoint) — never presented as Authorization: Bearer.
        SetBearer(challengeToken);
        var response = await _client.GetAsync("/api/bedrock/sessions");
        SetBearer(null);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "a captured MFA-challenge token must never be usable as a normal bearer token — it has no token_type == \"access\" claim");
    }

    [Fact]
    public async Task CapturedStepUpToken_ReplayedAsBearerToken_Returns403OnDefaultPolicyEndpoint()
    {
        var email = "stepup-steptoken-replay@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var stepUpToken = await GetStepUpTokenAsync();

        // The step-up token is only ever meant to be presented via the X-Step-Up-Token header
        // on [RequiresStepUp] endpoints — never as Authorization: Bearer.
        SetBearer(stepUpToken);
        var response = await _client.GetAsync("/api/bedrock/sessions");
        SetBearer(null);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "a captured step-up token must never be usable as a normal bearer token — it has no token_type == \"access\" claim");
    }

    // -------------------------------------------------------------------------
    // [RequiresStepUp] enforcement — tested via DELETE /api/bedrock/2fa
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ProtectedEndpoint_WithoutStepUpToken_Returns403()
    {
        var email = "stepup-notoken@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        // No X-Step-Up-Token header
        var response = await _client.PostAsync("/api/bedrock/2fa/disable", null);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithValidStepUpToken_Returns200()
    {
        var email = "stepup-valid@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var stepUpToken = await GetStepUpTokenAsync();

        _client.DefaultRequestHeaders.Add("X-Step-Up-Token", stepUpToken);
        var response = await _client.PostAsync("/api/bedrock/2fa/disable", null);
        _client.DefaultRequestHeaders.Remove("X-Step-Up-Token");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ProtectedEndpoint_StepUpTokenReusedOnSecondCall_Returns403()
    {
        var email = "stepup-reuse@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var stepUpToken = await GetStepUpTokenAsync();

        // First use: succeeds
        _client.DefaultRequestHeaders.Add("X-Step-Up-Token", stepUpToken);
        var first = await _client.PostAsJsonAsync(
            "/api/bedrock/2fa/recovery-codes/regenerate", new { });
        _client.DefaultRequestHeaders.Remove("X-Step-Up-Token");
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        // Second use with same token: rejected
        _client.DefaultRequestHeaders.Add("X-Step-Up-Token", stepUpToken);
        var second = await _client.PostAsJsonAsync(
            "/api/bedrock/2fa/recovery-codes/regenerate", new { });
        _client.DefaultRequestHeaders.Remove("X-Step-Up-Token");
        second.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // -------------------------------------------------------------------------
    // GET /api/bedrock/2fa/recovery-codes
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetRemainingRecoveryCodes_WithStepUp_ReturnsCount()
    {
        var email = "stepup-rcc@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var stepUpToken = await GetStepUpTokenAsync();
        _client.DefaultRequestHeaders.Add("X-Step-Up-Token", stepUpToken);
        var response = await _client.GetAsync("/api/bedrock/2fa/recovery-codes");
        _client.DefaultRequestHeaders.Remove("X-Step-Up-Token");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<RemainingRecoveryCodesResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.RemainingCount.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task GetRemainingRecoveryCodes_WithoutStepUp_Returns403()
    {
        var email = "stepup-rcc-noauth@example.com";
        var tokens = await RegisterActivateEnableMfaAndLoginAsync(email);
        SetBearer(tokens.AccessToken);

        var response = await _client.GetAsync("/api/bedrock/2fa/recovery-codes");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task RegisterAndActivateAsync(string email)
    {
        await _client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));

        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        var tokenHash = _server.DbContext.EmailVerificationTokens.First(t => t.UserId == userId).TokenHash;

        await _client.PostAsJsonAsync("/api/bedrock/auth/confirm-email", new ConfirmEmailRequest(tokenHash));
    }

    private async Task<LoginResponse> LoginNoMfaAsync(string email)
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));

        var body = await ReadAsync<BedrockResponse<LoginResponse>>(response);
        return body.Data!;
    }

    private async Task<LoginResponse> RegisterActivateEnableMfaAndLoginAsync(string email)
    {
        await RegisterAndActivateAsync(email);

        // Enable EmailOtp MFA directly on the credential
        var credential = _server.DbContext.UserCredentials.First(c => c.Email == email);
        credential.EnableMfa(MfaMethod.EmailOtp);
        await _server.DbContext.SaveChangesAsync();

        // Add recovery codes so regenerate-recovery-codes has something to work with
        var userId = credential.UserId;
        _server.DbContext.RecoveryCodes.Add(
            Crestacle.Bedrock.Core.Entities.RecoveryCode.Create(userId, "fakehash1"));
        _server.DbContext.RecoveryCodes.Add(
            Crestacle.Bedrock.Core.Entities.RecoveryCode.Create(userId, "fakehash2"));
        await _server.DbContext.SaveChangesAsync();

        // Login → triggers MFA challenge
        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var loginBody = await ReadAsync<BedrockResponse<LoginResponse>>(loginResp);
        var challengeToken = loginBody.Data!.ChallengeToken!;

        // Verify MFA with the fake OTP code
        var mfaResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/verify-2fa",
            new VerifyMfaRequest(challengeToken, FakeOtpService.FixedCode));
        var mfaBody = await ReadAsync<BedrockResponse<LoginResponse>>(mfaResp);
        return mfaBody.Data!;
    }

    private async Task<Guid> InitiateStepUpAsync()
    {
        var response = await _client.PostAsync("/api/bedrock/step-up/initiate", null);
        response.EnsureSuccessStatusCode();
        var body = await ReadAsync<BedrockResponse<StepUpInitiateResponse>>(response);
        return body.Data!.ChallengeId;
    }

    private async Task<string> GetStepUpTokenAsync()
    {
        var challengeId = await InitiateStepUpAsync();

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/step-up/verify",
            new VerifyStepUpRequest(challengeId, FakeOtpService.FixedCode));
        response.EnsureSuccessStatusCode();
        var body = await ReadAsync<BedrockResponse<StepUpVerifyResponse>>(response);
        return body.Data!.StepUpToken;
    }

    private void SetBearer(string? token)
        => _client.DefaultRequestHeaders.Authorization =
            token is null ? null : new AuthenticationHeaderValue("Bearer", token);

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(json, JsonOptions)!;
    }

    public void Dispose() => _server.Dispose();
}
