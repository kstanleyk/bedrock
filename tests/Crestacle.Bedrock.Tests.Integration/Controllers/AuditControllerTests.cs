using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

public sealed class AuditControllerTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";

    public AuditControllerTests()
    {
        _server = new BedrockTestServer(
            configureServices: services => services.AddSingleton<IEmailSender>(_emailSender));
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // GET /api/bedrock/audit
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Query_WithoutAuth_Returns401()
    {
        var response = await _client.GetAsync("/api/bedrock/audit");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Query_WithAuth_Returns200AndAuditEntries()
    {
        var email = "audit-basic@example.com";
        var (userId, accessToken) = await RegisterActivateAndLoginAsync(email);
        SetBearer(accessToken);

        var response = await _client.GetAsync("/api/bedrock/audit");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<AuditQueryResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.Items.Should().NotBeEmpty();
        body.Data.TotalCount.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Query_FilterByEventType_ReturnsOnlyMatchingEntries()
    {
        var email = "audit-filter@example.com";
        var (_, accessToken) = await RegisterActivateAndLoginAsync(email);
        SetBearer(accessToken);

        var response = await _client.GetAsync(
            $"/api/bedrock/audit?eventType={(int)AuditEventType.LoginSucceeded}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<AuditQueryResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.Items.Should().AllSatisfy(e => e.EventType.Should().Be(AuditEventType.LoginSucceeded));
    }

    [Fact]
    public async Task Query_FilterByUserId_ReturnsOnlyThatUsersEntries()
    {
        var email1 = "audit-user1@example.com";
        var email2 = "audit-user2@example.com";
        var (userId1, token1) = await RegisterActivateAndLoginAsync(email1);
        var (_, _) = await RegisterActivateAndLoginAsync(email2);
        SetBearer(token1);

        var response = await _client.GetAsync($"/api/bedrock/audit?userId={userId1}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<AuditQueryResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.Items.Should().AllSatisfy(e => e.UserId.Should().Be(userId1));
    }

    [Fact]
    public async Task Query_PageSize1_ReturnsSingleItemWithCorrectTotalCount()
    {
        var email = "audit-page@example.com";
        var (_, accessToken) = await RegisterActivateAndLoginAsync(email);
        SetBearer(accessToken);

        var response = await _client.GetAsync("/api/bedrock/audit?page=1&pageSize=1");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<AuditQueryResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.Items.Should().HaveCount(1);
        body.Data.TotalCount.Should().BeGreaterThan(1);
    }

    [Fact]
    public async Task Query_PageSizeExceedsMax_ClampedTo200()
    {
        var email = "audit-clamp@example.com";
        var (_, accessToken) = await RegisterActivateAndLoginAsync(email);
        SetBearer(accessToken);

        // pageSize=500 should not error — it is clamped to 200 server-side
        var response = await _client.GetAsync("/api/bedrock/audit?pageSize=500");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<AuditQueryResponse>>(response);
        body.Success.Should().BeTrue();
        body.Data!.Items.Count.Should().BeLessThanOrEqualTo(200);
    }

    [Fact]
    public async Task Query_ResultsOrderedByOccurredAtDescending()
    {
        var email = "audit-order@example.com";
        var (_, accessToken) = await RegisterActivateAndLoginAsync(email);
        SetBearer(accessToken);

        var response = await _client.GetAsync("/api/bedrock/audit");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync<BedrockResponse<AuditQueryResponse>>(response);
        var times = body.Data!.Items.Select(e => e.OccurredAt).ToList();
        times.Should().BeInDescendingOrder();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task<(Guid UserId, string AccessToken)> RegisterActivateAndLoginAsync(string email)
    {
        await _client.PostAsJsonAsync("/api/bedrock/auth/register", new RegisterRequest(email, ValidPassword));

        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);
        await _client.PostAsJsonAsync("/api/bedrock/auth/confirm-email", new ConfirmEmailRequest(rawToken));
        var userId = _server.DbContext.UserCredentials.First(c => c.Email == email).UserId;

        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));
        var loginBody = await ReadAsync<BedrockResponse<LoginResponse>>(loginResp);
        return (userId, loginBody.Data!.AccessToken!);
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
