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

/// <summary>F7 — Invitation system integration tests.</summary>
public sealed class InvitationTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string AdminPassword = "AdminP@ssword1!";
    private const string InviteePassword = "InviteeP@ssword1!";

    public InvitationTests()
    {
        _server = new BedrockTestServer(
            configureServices: s =>
            {
                s.AddSingleton<IBedrockClaimsEnricher, AdminClaimsEnricher>();
                s.AddSingleton<IEmailSender>(_emailSender);
            });
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // Happy path — create then accept
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateInvitation_ThenAccept_AccountIsActiveAndTokensReturned()
    {
        var adminEmail = "inv-admin@example.com";
        var inviteeEmail = "invitee@example.com";

        await RegisterAndActivateAsync(adminEmail);
        var adminToken = await GetTokenAsync(adminEmail, AdminPassword);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", adminToken);

        // Admin creates invitation
        var createResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/admin/invitations",
            new CreateInvitationRequest(inviteeEmail, "member"));

        createResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // The real raw token the invitee would receive by email (simulates clicking the link).
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(inviteeEmail)!);

        _client.DefaultRequestHeaders.Authorization = null;

        // Invitee accepts the invitation
        var acceptResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/accept-invitation",
            new AcceptInvitationRequest(rawToken, InviteePassword));

        acceptResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadBedrockResponseAsync<LoginResponse>(acceptResponse);
        body.Data.Should().NotBeNull();
        body.Data!.AccessToken.Should().NotBeNullOrWhiteSpace();
        body.Data!.RefreshToken.Should().NotBeNullOrWhiteSpace();
        body.Data!.AccessTokenExpiresAt.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task AcceptInvitation_AccountIsActiveAndEmailConfirmed()
    {
        var adminEmail = "inv-admin2@example.com";
        var inviteeEmail = "invitee2@example.com";

        await RegisterAndActivateAsync(adminEmail);
        var adminToken = await GetTokenAsync(adminEmail, AdminPassword);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", adminToken);

        await _client.PostAsJsonAsync(
            "/api/bedrock/admin/invitations",
            new CreateInvitationRequest(inviteeEmail));

        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(inviteeEmail)!);

        _client.DefaultRequestHeaders.Authorization = null;

        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/accept-invitation",
            new AcceptInvitationRequest(rawToken, InviteePassword));

        var credential = _server.DbContext.UserCredentials
            .First(c => c.Email == inviteeEmail);
        credential.EmailConfirmed.Should().BeTrue();
        credential.Status.Should().Be(AccountStatus.Active);
    }

    [Fact]
    public async Task AcceptInvitation_InvitationMarkedAccepted()
    {
        var adminEmail = "inv-admin3@example.com";
        var inviteeEmail = "invitee3@example.com";

        await RegisterAndActivateAsync(adminEmail);
        var adminToken = await GetTokenAsync(adminEmail, AdminPassword);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", adminToken);

        await _client.PostAsJsonAsync(
            "/api/bedrock/admin/invitations",
            new CreateInvitationRequest(inviteeEmail));

        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(inviteeEmail)!);

        _client.DefaultRequestHeaders.Authorization = null;

        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/accept-invitation",
            new AcceptInvitationRequest(rawToken, InviteePassword));

        var invitation = _server.DbContext.Invitations
            .First(i => i.TargetEmail == inviteeEmail);
        invitation.AcceptedAt.Should().NotBeNull();
        invitation.IsValid.Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // Double-acceptance is rejected
    // -------------------------------------------------------------------------

    [Fact]
    public async Task AcceptInvitation_Twice_SecondAttemptReturns400()
    {
        var adminEmail = "inv-admin4@example.com";
        var inviteeEmail = "invitee4@example.com";

        await RegisterAndActivateAsync(adminEmail);
        var adminToken = await GetTokenAsync(adminEmail, AdminPassword);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", adminToken);

        await _client.PostAsJsonAsync(
            "/api/bedrock/admin/invitations",
            new CreateInvitationRequest(inviteeEmail));

        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(inviteeEmail)!);

        _client.DefaultRequestHeaders.Authorization = null;

        // First acceptance succeeds
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/accept-invitation",
            new AcceptInvitationRequest(rawToken, InviteePassword));

        // Second attempt must fail — invitation already accepted and email already registered
        var secondResponse = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/accept-invitation",
            new AcceptInvitationRequest(rawToken, InviteePassword));

        secondResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // Invalid / unknown token
    // -------------------------------------------------------------------------

    [Fact]
    public async Task AcceptInvitation_UnknownToken_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/accept-invitation",
            new AcceptInvitationRequest("deadbeefdeadbeef", InviteePassword));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // -------------------------------------------------------------------------
    // Admin endpoint requires BedrockAdmin policy
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateInvitation_WithoutAdminClaim_Returns403()
    {
        var plainEmailSender = new CapturingEmailSender();
        using var plainServer = new BedrockTestServer(
            configureServices: s => s.AddSingleton<IEmailSender>(plainEmailSender));
        using var plainClient = plainServer.Client;

        var email = "inv-noadmin@example.com";
        await RegisterAndActivateAsync(email, plainClient, plainEmailSender);
        var token = await GetTokenAsync(email, AdminPassword, plainClient);
        plainClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await plainClient.PostAsJsonAsync(
            "/api/bedrock/admin/invitations",
            new CreateInvitationRequest("target@example.com"));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task RegisterAndActivateAsync(string email)
        => await RegisterAndActivateAsync(email, _client, _emailSender);

    private static async Task RegisterAndActivateAsync(
        string email, HttpClient client, CapturingEmailSender emailSender)
    {
        await client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, AdminPassword));

        var rawToken = CapturingEmailSender.ExtractToken(emailSender.LastBodyFor(email)!);

        await client.PostAsJsonAsync("/api/bedrock/auth/confirm-email", new ConfirmEmailRequest(rawToken));
    }

    private async Task<string> GetTokenAsync(string email, string password)
        => await GetTokenAsync(email, password, _client);

    private static async Task<string> GetTokenAsync(string email, string password, HttpClient client)
    {
        var response = await client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, password));
        var json = await response.Content.ReadAsStringAsync();
        var body = JsonSerializer.Deserialize<BedrockResponse<LoginResponse>>(json, JsonOptions)!;
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
