using System.Net;
using System.Net.Http.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

/// <summary>
/// Slice H8: the DataAnnotations added to request DTOs in
/// <see cref="Crestacle.Bedrock.AspNetCore.Models"/> must reject malformed/empty/oversized input
/// at model binding (400, before the request ever reaches service logic) while still accepting a
/// genuinely well-formed payload — the real regression risk of adding validation attributes after
/// the fact.
/// </summary>
public sealed class RequestDtoValidationTests : IDisposable
{
    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";

    public RequestDtoValidationTests()
    {
        _server = new BedrockTestServer(
            configureServices: services => services.AddSingleton<IEmailSender>(_emailSender));
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/register
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Register_EmptyEmailAndPassword_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(string.Empty, string.Empty));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_MalformedEmail_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest("not-an-email", ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_OversizedPassword_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest("ctrl-oversized-pw@example.com", new string('a', 300) + "A1!"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_OversizedEmail_Returns400()
    {
        var oversizedLocalPart = new string('a', 250);
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest($"{oversizedLocalPart}@example.com", ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_WellFormedPayload_Returns200()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest("ctrl-h8-wellformed-register@example.com", ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "a well-formed register payload must not be rejected by the new validation attributes");
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/login
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Login_EmptyEmailAndPassword_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(string.Empty, string.Empty));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Login_OversizedPassword_Returns400()
    {
        // Oversized input must be rejected at model binding, before it ever reaches credential
        // lookup -- even against a non-existent account.
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest("ctrl-h8-login-oversized@example.com", new string('a', 300)));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Login_WellFormedPayload_Returns200()
    {
        var email = "ctrl-h8-wellformed-login@example.com";
        await RegisterAndActivateAsync(email);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "a well-formed login payload must not be rejected by the new validation attributes");
    }

    // -------------------------------------------------------------------------
    // POST /api/bedrock/auth/reset-password
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ResetPassword_EmptyTokenAndPassword_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/reset-password",
            new ResetPasswordRequest(string.Empty, string.Empty));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ResetPassword_OversizedNewPassword_Returns400()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/reset-password",
            new ResetPasswordRequest("some-token", new string('a', 300) + "A1!"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ResetPassword_WellFormedPayload_Returns200()
    {
        var email = "ctrl-h8-wellformed-reset@example.com";
        await RegisterAndActivateAsync(email);

        await _client.PostAsJsonAsync("/api/bedrock/auth/forgot-password", new ForgotPasswordRequest(email));
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);

        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/reset-password",
            new ResetPasswordRequest(rawToken, "AnotherValidP@ssword2!"));

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "a well-formed reset-password payload must not be rejected by the new validation attributes");
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

    public void Dispose() => _server.Dispose();
}
