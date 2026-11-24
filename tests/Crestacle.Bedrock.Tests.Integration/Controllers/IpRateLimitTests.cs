using System.Net;
using System.Net.Http.Json;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers;

/// <summary>
/// F5 — IP-based rate limiting integration tests.
/// Uses MaxFailedAttemptsPerIp = 3 to keep test execution fast.
/// </summary>
public sealed class IpRateLimitTests : IDisposable
{
    private const int TestMaxFails = 3;
    private const string ValidPassword = "ValidP@ssword1!";
    private const string WrongPassword = "WrongPassword999!";

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;

    public IpRateLimitTests()
    {
        _server = new BedrockTestServer(configureOptions: opts =>
        {
            opts.IpRateLimit.Enabled = true;
            opts.IpRateLimit.MaxFailedAttemptsPerIp = TestMaxFails;
            opts.IpRateLimit.IpLockoutWindow = TimeSpan.FromMinutes(10);
            opts.IpRateLimit.IpLockoutDuration = TimeSpan.FromMinutes(15);
            // Raise per-credential lockout well above IP limit so it does not fire first
            opts.Lockout.MaxFailedAttempts = 50;
        });
        _client = _server.Client;
    }

    // -------------------------------------------------------------------------
    // Happy path — limit not yet reached
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Login_WithinIpLimit_DoesNotReturn429()
    {
        var email = "ip-within@example.com";
        await RegisterAndActivateAsync(email);

        for (var i = 0; i < TestMaxFails; i++)
        {
            var resp = await _client.PostAsJsonAsync(
                "/api/bedrock/auth/login",
                new LoginRequest(email, WrongPassword));

            // Wrong password → 401 Unauthorized, not 429
            resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
                because: $"attempt #{i + 1} is within the IP limit of {TestMaxFails}");
        }
    }

    // -------------------------------------------------------------------------
    // IP rate limit exceeded → 429 with Retry-After
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Login_ExceedsIpLimit_Returns429WithRetryAfter()
    {
        var email = "ip-exceed@example.com";
        await RegisterAndActivateAsync(email);

        // Exhaust the IP failure budget with wrong-password attempts
        for (var i = 0; i < TestMaxFails; i++)
        {
            await _client.PostAsJsonAsync(
                "/api/bedrock/auth/login",
                new LoginRequest(email, WrongPassword));
        }

        // The (TestMaxFails + 1)th attempt must be blocked at the IP level
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, WrongPassword));

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        response.Headers.Contains("Retry-After").Should().BeTrue(
            because: "RFC 6585 requires Retry-After on 429 responses");
        var retryAfter = int.Parse(response.Headers.GetValues("Retry-After").First());
        retryAfter.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Login_ExceedsIpLimit_CorrectPasswordAlsoBlocked()
    {
        var email = "ip-correct-blocked@example.com";
        await RegisterAndActivateAsync(email);

        // Burn the budget using unknown-email attempts (these still increment the IP counter)
        for (var i = 0; i < TestMaxFails; i++)
        {
            await _client.PostAsJsonAsync(
                "/api/bedrock/auth/login",
                new LoginRequest($"ghost-{i}@example.com", WrongPassword));
        }

        // Even a correct-password attempt must be blocked before the DB lookup
        var response = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(email, ValidPassword));

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }

    // -------------------------------------------------------------------------
    // Per-credential lockout still functions independently
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Login_PerCredentialLockout_StillFunctionsWhenIpLimitNotReached()
    {
        // A server with a very low per-credential limit but a high IP limit
        using var server = new BedrockTestServer(configureOptions: opts =>
        {
            opts.IpRateLimit.Enabled = true;
            opts.IpRateLimit.MaxFailedAttemptsPerIp = 1000;
            opts.Lockout.MaxFailedAttempts = 2;
            opts.Lockout.Duration = TimeSpan.FromSeconds(30);
        });
        using var client = server.Client;

        var email = "cred-lock@example.com";
        await RegisterAndActivateAsync(email, client, server);

        // Two wrong attempts trigger per-credential lockout
        await client.PostAsJsonAsync("/api/bedrock/auth/login", new LoginRequest(email, WrongPassword));
        await client.PostAsJsonAsync("/api/bedrock/auth/login", new LoginRequest(email, WrongPassword));

        // Third attempt — 423 Locked (locked result), NOT 429
        var resp = await client.PostAsJsonAsync("/api/bedrock/auth/login", new LoginRequest(email, WrongPassword));
        resp.StatusCode.Should().Be((HttpStatusCode)423,
            because: "per-credential lockout returns 423, not 429 (IP limit is not reached)");
    }

    // -------------------------------------------------------------------------
    // Disabled IP rate limiting
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Login_IpRateLimitDisabled_NeverReturns429ForIp()
    {
        using var server = new BedrockTestServer(configureOptions: opts =>
        {
            opts.IpRateLimit.Enabled = false;
            opts.IpRateLimit.MaxFailedAttemptsPerIp = 1; // would trigger immediately if enabled
            opts.Lockout.MaxFailedAttempts = 1000;
        });
        using var client = server.Client;

        var email = "ip-disabled@example.com";
        await RegisterAndActivateAsync(email, client, server);

        for (var i = 0; i < 5; i++)
        {
            var resp = await client.PostAsJsonAsync(
                "/api/bedrock/auth/login",
                new LoginRequest(email, WrongPassword));

            resp.StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests,
                because: "IP rate limiting is disabled");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task RegisterAndActivateAsync(string email)
        => await RegisterAndActivateAsync(email, _client, _server);

    private static async Task RegisterAndActivateAsync(
        string email, HttpClient client, BedrockTestServer server)
    {
        await client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(email, ValidPassword));

        var userId = server.DbContext.UserCredentials.First(c => c.Email == email).UserId;
        var tokenHash = server.DbContext.EmailVerificationTokens.First(t => t.UserId == userId).TokenHash;

        await client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest(tokenHash));
    }

    public void Dispose() => _server.Dispose();
}
