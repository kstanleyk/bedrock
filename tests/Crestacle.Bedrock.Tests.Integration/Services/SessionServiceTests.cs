using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.EntityFramework;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Services;

public sealed class SessionServiceTests : IDisposable
{
    private readonly TestBedrockContext _context;
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;
    private readonly ICredentialService _credentialService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ISessionService _sessionService;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";
    private const string TestSigningKey = "Bedrock-Integration-Test-Signing-Key-32B!";

    public SessionServiceTests()
    {
        (_context, _connection) = DbContextFactory.Create();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<BedrockContext>(_context);
        services.AddSingleton<IEmailSender>(_emailSender);
        services.AddBedrockEntityFramework<BedrockContext>();
        services.AddBedrockAspNetCore(opts =>
        {
            opts.Jwt.SigningKey = TestSigningKey;
            opts.Jwt.Issuer = "test";
            opts.Jwt.Audience = "test";
            opts.Password.MinLength = 12;
            opts.Lockout.MaxFailedAttempts = 5;
            opts.Lockout.Duration = TimeSpan.FromSeconds(30);
            opts.Session.MaxConcurrentSessions = 3;
            opts.TokenExpiry.EmailVerificationToken = TimeSpan.FromHours(24);
            opts.AnomalyDetection.Enabled = true;
        });
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

        var sp = services.BuildServiceProvider();
        _credentialService = sp.GetRequiredService<ICredentialService>();
        _refreshTokenService = sp.GetRequiredService<IRefreshTokenService>();
        _sessionService = sp.GetRequiredService<ISessionService>();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task<Guid> RegisterAndActivateAsync(string email)
    {
        var userId = Guid.NewGuid();
        await _credentialService.RegisterAsync(userId, email, ValidPassword);
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);
        await _credentialService.ConfirmEmailAsync(rawToken);
        return userId;
    }

    private async Task<string> LoginAndIssueAsync(Guid userId, string email, string fingerprint = "fp-default", string ip = "1.2.3.4")
    {
        await _credentialService.LoginFirstFactorAsync(email, ValidPassword, ip, "TestAgent/1.0", fingerprint);
        var tokens = await _refreshTokenService.IssueAsync(userId, email, Array.Empty<string>(), ip, "TestAgent/1.0", fingerprint);
        return tokens.RefreshToken;
    }

    // -------------------------------------------------------------------------
    // GetActiveSessionsAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetActiveSessionsAsync_AfterLogin_ReturnsSingleSession()
    {
        var userId = await RegisterAndActivateAsync("sessions-list@example.com");
        await LoginAndIssueAsync(userId, "sessions-list@example.com");

        var sessions = await _sessionService.GetActiveSessionsAsync(userId);

        sessions.Should().HaveCount(1);
        sessions[0].UserId.Should().Be(userId);
        sessions[0].IsActive.Should().BeTrue();
    }

    [Fact]
    public async Task GetActiveSessionsAsync_NoSessions_ReturnsEmpty()
    {
        var userId = await RegisterAndActivateAsync("sessions-empty@example.com");

        var sessions = await _sessionService.GetActiveSessionsAsync(userId);

        sessions.Should().BeEmpty();
    }

    // -------------------------------------------------------------------------
    // RevokeSessionAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RevokeSessionAsync_ValidSession_RevokesSessionAndRefreshToken()
    {
        var userId = await RegisterAndActivateAsync("sessions-revoke@example.com");
        await LoginAndIssueAsync(userId, "sessions-revoke@example.com");

        var sessions = await _sessionService.GetActiveSessionsAsync(userId);
        sessions.Should().HaveCount(1);

        await _sessionService.RevokeSessionAsync(sessions[0].Id, userId, "1.2.3.4");

        var afterRevoke = await _sessionService.GetActiveSessionsAsync(userId);
        afterRevoke.Should().BeEmpty();
    }

    [Fact]
    public async Task RevokeSessionAsync_WrongUser_ThrowsForbidden()
    {
        var userId = await RegisterAndActivateAsync("sessions-idor-owner@example.com");
        await LoginAndIssueAsync(userId, "sessions-idor-owner@example.com");

        var sessions = await _sessionService.GetActiveSessionsAsync(userId);

        var otherUserId = Guid.NewGuid();
        var act = async () => await _sessionService.RevokeSessionAsync(sessions[0].Id, otherUserId, "1.2.3.4");

        await act.Should().ThrowAsync<BedrockForbiddenException>();
    }

    [Fact]
    public async Task RevokeSessionAsync_UnknownSessionId_ThrowsNotFound()
    {
        var act = async () => await _sessionService.RevokeSessionAsync(Guid.NewGuid(), Guid.NewGuid(), "1.2.3.4");
        await act.Should().ThrowAsync<BedrockNotFoundException>();
    }

    [Fact]
    public async Task RevokeSessionAsync_AlreadyRevoked_DoesNotThrow()
    {
        var userId = await RegisterAndActivateAsync("sessions-double-revoke@example.com");
        await LoginAndIssueAsync(userId, "sessions-double-revoke@example.com");

        var sessions = await _sessionService.GetActiveSessionsAsync(userId);

        await _sessionService.RevokeSessionAsync(sessions[0].Id, userId, "1.2.3.4");

        // Second revoke on same session — should not throw
        var act = async () => await _sessionService.RevokeSessionAsync(sessions[0].Id, userId, "1.2.3.4");
        await act.Should().NotThrowAsync();
    }

    // -------------------------------------------------------------------------
    // RevokeAllSessionsAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAllSessionsAsync_MultipleSessions_RevokesAll()
    {
        var userId = await RegisterAndActivateAsync("sessions-revoke-all@example.com");
        await LoginAndIssueAsync(userId, "sessions-revoke-all@example.com", "fp-1");
        await LoginAndIssueAsync(userId, "sessions-revoke-all@example.com", "fp-2");

        var before = await _sessionService.GetActiveSessionsAsync(userId);
        before.Should().HaveCount(2);

        await _sessionService.RevokeAllSessionsAsync(userId, "1.2.3.4");

        var after = await _sessionService.GetActiveSessionsAsync(userId);
        after.Should().BeEmpty();
    }

    // -------------------------------------------------------------------------
    // MaxConcurrentSessions eviction
    // -------------------------------------------------------------------------

    [Fact]
    public async Task MaxConcurrentSessions_ExceedLimit_EvictsOldestSession()
    {
        var userId = await RegisterAndActivateAsync("sessions-evict@example.com");

        // Create 3 sessions (MaxConcurrentSessions = 3)
        var rt1 = await LoginAndIssueAsync(userId, "sessions-evict@example.com", "fp-a");
        var rt2 = await LoginAndIssueAsync(userId, "sessions-evict@example.com", "fp-b");
        var rt3 = await LoginAndIssueAsync(userId, "sessions-evict@example.com", "fp-c");

        var atLimit = await _sessionService.GetActiveSessionsAsync(userId);
        atLimit.Should().HaveCount(3);

        // 4th login should evict the oldest
        await LoginAndIssueAsync(userId, "sessions-evict@example.com", "fp-d");

        var afterEviction = await _sessionService.GetActiveSessionsAsync(userId);
        afterEviction.Should().HaveCount(3);

        // Oldest session's refresh token should no longer be refreshable
        var refreshAttempt = async () => await _refreshTokenService.RefreshAsync(rt1, "1.2.3.4", "TestAgent/1.0", "fp-a");
        await refreshAttempt.Should().ThrowAsync<BedrockValidationException>();
    }

    // -------------------------------------------------------------------------
    // Anomaly detection
    // -------------------------------------------------------------------------

    [Fact]
    public async Task AnomalyDetection_FirstLogin_NoChallenge()
    {
        var userId = await RegisterAndActivateAsync("anomaly-first@example.com");

        var result = await _credentialService.LoginFirstFactorAsync(
            "anomaly-first@example.com", ValidPassword, "1.2.3.4", "TestAgent/1.0", "fp-known");

        // First login: no known device baseline, not anomalous
        result.Succeeded.Should().BeTrue();
        result.Challenge.Should().BeNull();
    }

    [Fact]
    public async Task AnomalyDetection_KnownDevice_SecondLogin_NoChallenge()
    {
        var userId = await RegisterAndActivateAsync("anomaly-known@example.com");

        // First login — records device
        await _credentialService.LoginFirstFactorAsync(
            "anomaly-known@example.com", ValidPassword, "1.2.3.4", "TestAgent/1.0", "fp-known");

        // Second login from same fingerprint — known device, no anomaly
        var result = await _credentialService.LoginFirstFactorAsync(
            "anomaly-known@example.com", ValidPassword, "1.2.3.4", "TestAgent/1.0", "fp-known");

        result.Succeeded.Should().BeTrue();
        result.Challenge.Should().BeNull();
    }

    [Fact]
    public async Task AnomalyDetection_UnknownDevice_AfterFirstLogin_TriggersMfaChallenge()
    {
        var userId = await RegisterAndActivateAsync("anomaly-unknown@example.com");

        // First login establishes the device baseline
        await _credentialService.LoginFirstFactorAsync(
            "anomaly-unknown@example.com", ValidPassword, "1.2.3.4", "TestAgent/1.0", "fp-original");

        // Second login from a different fingerprint — anomalous
        var result = await _credentialService.LoginFirstFactorAsync(
            "anomaly-unknown@example.com", ValidPassword, "1.2.3.4", "TestAgent/1.0", "fp-different");

        result.Succeeded.Should().BeTrue();
        result.Challenge.Should().NotBeNull();
        result.Challenge!.Method.Should().Be(Core.Enumerations.MfaMethod.EmailOtp);
    }

    public void Dispose()
    {
        _context.Dispose();
        _connection.Dispose();
    }
}
