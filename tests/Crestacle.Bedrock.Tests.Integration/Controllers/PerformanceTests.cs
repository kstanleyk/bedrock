using System.Diagnostics;
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

/// <summary>
/// G4 — End-to-end timing for the token refresh round-trip.
/// Covers: token hash, DB read ×3, DB write ×4 (revoke old token, add new token,
/// update session, add audit entry), cache write (JTI blacklist), SaveChangesAsync.
/// </summary>
public sealed class PerformanceTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly BedrockTestServer _server;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    private const string Email = "perf-refresh@example.com";
    private const string Password = "ValidP@ssword1!";

    // CI threshold: 300 ms average over 10 calls using SQLite in-memory + MemoryBedrockCache.
    // Production target against a real database will be higher and should be measured separately.
    private const double ThresholdMs = 300.0;

    public PerformanceTests()
    {
        _server = new BedrockTestServer(
            configureServices: services => services.AddSingleton<IEmailSender>(_emailSender));
        _client = _server.Client;
    }

    [Fact]
    public async Task Refresh_EndToEnd_AverageUnder300ms()
    {
        // Arrange — register, confirm email, login to obtain an initial refresh token
        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/register",
            new RegisterRequest(Email, Password));

        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(Email)!);

        await _client.PostAsJsonAsync(
            "/api/bedrock/auth/confirm-email",
            new ConfirmEmailRequest(rawToken));

        var loginResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/login",
            new LoginRequest(Email, Password));
        var loginBody = await loginResp.Content
            .ReadFromJsonAsync<BedrockResponse<LoginResponse>>(JsonOptions);
        var refreshToken = loginBody!.Data!.RefreshToken!;

        const int iterations = 10;

        // Warm-up: absorb JIT, EF Core model compilation, and first-call SQLite page cache priming.
        var warmupResp = await _client.PostAsJsonAsync(
            "/api/bedrock/auth/refresh",
            new RefreshRequest(refreshToken));
        var warmupBody = await warmupResp.Content
            .ReadFromJsonAsync<BedrockResponse<TokenResponse>>(JsonOptions);
        refreshToken = warmupBody!.Data!.RefreshToken;

        // Timed loop — each iteration rotates the token so the DB state is realistic
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < iterations; i++)
        {
            var resp = await _client.PostAsJsonAsync(
                "/api/bedrock/auth/refresh",
                new RefreshRequest(refreshToken));
            var body = await resp.Content
                .ReadFromJsonAsync<BedrockResponse<TokenResponse>>(JsonOptions);
            refreshToken = body!.Data!.RefreshToken;
        }
        sw.Stop();

        var avgMs = sw.Elapsed.TotalMilliseconds / iterations;
        avgMs.Should().BeLessThan(ThresholdMs,
            because: $"RefreshAsync end-to-end average over {iterations} calls must be under " +
                     $"{ThresholdMs} ms (SQLite in-memory; covers token hash, 3 DB reads, " +
                     $"4 DB writes, 1 cache write)");
    }

    public void Dispose() => _server.Dispose();
}
