using System.Diagnostics;
using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Crestacle.Bedrock.EntityFramework;
using Crestacle.Bedrock.EntityFramework.Caching;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Services;

public sealed class RefreshTokenServiceTests : IDisposable
{
    private readonly TestBedrockContext _context;
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;
    private readonly IRefreshTokenService _service;
    private readonly ICredentialService _credentials;
    private readonly ITokenService _tokenService;
    private readonly IBedrockCache _cache;

    private const string TestSigningKey = "Bedrock-Integration-Test-Signing-Key-32B!";
    private const string ValidPassword = "ValidP@ssword1!";

    public RefreshTokenServiceTests()
    {
        (_context, _connection) = DbContextFactory.Create();

        var services = new ServiceCollection()
            .AddLogging()
            .AddMemoryCache()
            .AddSingleton<IBedrockCache, MemoryBedrockCache>()
            .AddSingleton<BedrockContext>(_context)
            .AddBedrockEntityFramework<BedrockContext>()
            .AddBedrockAspNetCore(opts =>
            {
                opts.Jwt.SigningKey = TestSigningKey;
                opts.Jwt.Issuer = "test";
                opts.Jwt.Audience = "test";
                opts.Password.MinLength = 12;
                opts.Session.MaxConcurrentSessions = 2;
            })
            .BuildServiceProvider();

        _service = services.GetRequiredService<IRefreshTokenService>();
        _credentials = services.GetRequiredService<ICredentialService>();
        _tokenService = services.GetRequiredService<ITokenService>();
        _cache = services.GetRequiredService<IBedrockCache>();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task<Guid> RegisterAndGetUserIdAsync(string email)
    {
        var userId = Guid.NewGuid();
        await _credentials.RegisterAsync(userId, email, ValidPassword);
        return userId;
    }

    // -------------------------------------------------------------------------
    // IssueAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IssueAsync_ValidInput_CreatesRefreshTokenAndSession()
    {
        var userId = await RegisterAndGetUserIdAsync("issue@example.com");

        var pair = await _service.IssueAsync(userId, "issue@example.com", [],
            "127.0.0.1", "TestAgent/1.0", "fp1");

        pair.AccessToken.Should().NotBeNullOrEmpty();
        pair.RefreshToken.Should().NotBeNullOrEmpty();
        pair.AccessTokenExpiresAt.Should().BeAfter(DateTime.UtcNow);

        _context.RefreshTokens.Any(t => t.UserId == userId).Should().BeTrue();
        _context.Sessions.Any(s => s.UserId == userId).Should().BeTrue();
    }

    [Fact]
    public async Task IssueAsync_ExceedsSessionLimit_EjectsOldestSession()
    {
        var userId = await RegisterAndGetUserIdAsync("limit@example.com");

        // Issue 2 tokens (fills the limit of 2)
        await _service.IssueAsync(userId, "limit@example.com", [], "127.0.0.1", "Agent", "fp1");
        await _service.IssueAsync(userId, "limit@example.com", [], "127.0.0.1", "Agent", "fp2");

        // Issue a 3rd — should evict the oldest
        await _service.IssueAsync(userId, "limit@example.com", [], "127.0.0.1", "Agent", "fp3");

        var activeSessions = _context.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .ToList();

        activeSessions.Should().HaveCount(2);
    }

    [Fact]
    public async Task IssueAsync_ConcurrentCallsAtLimit_NeverExceedsMaxConcurrentSessions()
    {
        // Arrange: use limit = 1 so the race is easy to observe.
        // Without the application-level lock both concurrent callers would read count = 0,
        // skip eviction, and each create a session — silently producing 2 active sessions.
        var (context, conn) = DbContextFactory.Create();
        using var _ = context;
        using var __ = conn;

        var sp = new ServiceCollection()
            .AddLogging()
            .AddSingleton<BedrockContext>(context)
            .AddBedrockEntityFramework<BedrockContext>()
            .AddBedrockAspNetCore(opts =>
            {
                opts.Jwt.SigningKey = TestSigningKey;
                opts.Jwt.Issuer = "test";
                opts.Jwt.Audience = "test";
                opts.Password.MinLength = 12;
                opts.Session.MaxConcurrentSessions = 1;
            })
            .BuildServiceProvider();

        var credentials = sp.GetRequiredService<ICredentialService>();
        var service = sp.GetRequiredService<IRefreshTokenService>();

        var userId = Guid.NewGuid();
        await credentials.RegisterAsync(userId, "concurrent@example.com", ValidPassword);

        // Act: two logins fired concurrently with the session count at zero (< limit of 1).
        await Task.WhenAll(
            service.IssueAsync(userId, "concurrent@example.com", [], "127.0.0.1", "Agent", "fp-a"),
            service.IssueAsync(userId, "concurrent@example.com", [], "127.0.0.1", "Agent", "fp-b")
        );

        // Assert: the lock serialises the two calls, so the second login evicts the first.
        // Exactly MaxConcurrentSessions = 1 active session must remain.
        var activeSessions = context.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .ToList();
        activeSessions.Should().HaveCount(1, "the session limit must be enforced under concurrency");

        var revokedCount = context.Sessions
            .Count(s => s.UserId == userId && s.RevokedAt != null);
        revokedCount.Should().Be(1, "the serialised second login must have evicted the first session");
    }

    // -------------------------------------------------------------------------
    // RefreshAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RefreshAsync_ValidToken_RotatesToken()
    {
        var userId = await RegisterAndGetUserIdAsync("refresh@example.com");
        var pair = await _service.IssueAsync(userId, "refresh@example.com", [],
            "127.0.0.1", "Agent", "fp1");

        var newPair = await _service.RefreshAsync(pair.RefreshToken, "127.0.0.1", "Agent", "fp1");

        newPair.AccessToken.Should().NotBeNullOrEmpty();
        newPair.RefreshToken.Should().NotBe(pair.RefreshToken);

        // Old token should be revoked
        var oldHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(pair.RefreshToken))).ToLowerInvariant();
        var oldToken = _context.RefreshTokens.First(t => t.TokenHash == oldHash);
        oldToken.RevokedAt.Should().NotBeNull();
        oldToken.ReplacedByTokenHash.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task RefreshAsync_CompletesWithinSla()
    {
        // IssueAsync warms up EF Core and the service code paths before the timed call.
        // Threshold: 500 ms for SQLite in-process. Production target is 50 ms against a
        // real relational DB — tighten this assertion when running against PostgreSQL.
        var userId = await RegisterAndGetUserIdAsync("perf-refresh@example.com");
        var pair = await _service.IssueAsync(userId, "perf-refresh@example.com", [],
            "127.0.0.1", "Agent", "fp1");

        var sw = Stopwatch.StartNew();
        _ = await _service.RefreshAsync(pair.RefreshToken, "127.0.0.1", "Agent", "fp1");
        sw.Stop();

        sw.ElapsedMilliseconds.Should().BeLessThan(500,
            because: "RefreshAsync must complete in under 500 ms with SQLite in-process " +
                     "(production target: 50 ms against a real DB)");
    }

    [Fact]
    public async Task RefreshAsync_InvalidToken_ThrowsValidation()
    {
        var act = async () => await _service.RefreshAsync("not-a-valid-token", "127.0.0.1", "Agent", "fp1");
        await act.Should().ThrowAsync<BedrockValidationException>();
    }

    [Fact]
    public async Task RefreshAsync_RevokedToken_ThrowsValidation()
    {
        var userId = await RegisterAndGetUserIdAsync("refresh-revoked@example.com");
        var pair = await _service.IssueAsync(userId, "refresh-revoked@example.com", [],
            "127.0.0.1", "Agent", "fp1");

        await _service.RevokeAsync(pair.RefreshToken, "127.0.0.1");

        var act = async () => await _service.RefreshAsync(pair.RefreshToken, "127.0.0.1", "Agent", "fp1");
        await act.Should().ThrowAsync<BedrockValidationException>();
    }

    [Fact]
    public async Task RefreshAsync_UpdatesSessionTokenHash()
    {
        var userId = await RegisterAndGetUserIdAsync("refresh-session@example.com");
        var pair = await _service.IssueAsync(userId, "refresh-session@example.com", [],
            "127.0.0.1", "Agent", "fp1");

        var newPair = await _service.RefreshAsync(pair.RefreshToken, "127.0.0.1", "Agent", "fp1");

        var newHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(newPair.RefreshToken))).ToLowerInvariant();

        _context.Sessions.Any(s => s.UserId == userId && s.TokenHash == newHash).Should().BeTrue();
    }

    // -------------------------------------------------------------------------
    // RevokeAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAsync_ValidToken_RevokesTokenAndSession()
    {
        var userId = await RegisterAndGetUserIdAsync("revoke@example.com");
        var pair = await _service.IssueAsync(userId, "revoke@example.com", [],
            "127.0.0.1", "Agent", "fp1");

        await _service.RevokeAsync(pair.RefreshToken, "127.0.0.1");

        var hash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(pair.RefreshToken))).ToLowerInvariant();

        _context.RefreshTokens.First(t => t.TokenHash == hash).RevokedAt.Should().NotBeNull();
        _context.Sessions.First(s => s.TokenHash == hash).RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RevokeAsync_UnknownToken_DoesNotThrow()
    {
        var act = async () => await _service.RevokeAsync("unknown-token", "127.0.0.1");
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RevokeAsync_WithExplicitJti_BlacklistsAccessToken()
    {
        var userId = await RegisterAndGetUserIdAsync("revoke-jti@example.com");
        var pair = await _service.IssueAsync(userId, "revoke-jti@example.com", [],
            "127.0.0.1", "Agent", "fp1");

        var fakeJti = Guid.NewGuid().ToString();

        await _service.RevokeAsync(pair.RefreshToken, "127.0.0.1",
            accessTokenJti: fakeJti,
            accessTokenRemainingLifetime: TimeSpan.FromMinutes(14));

        (await _cache.ExistsAsync($"Bedrock:revoked:{fakeJti}")).Should().BeTrue();
    }

    [Fact]
    public async Task RevokeAsync_WithoutExplicitJti_FallsBackToSessionsOwnAccessTokenAndBlacklistsIt()
    {
        // BedrockAuthController.Revoke/Logout call RevokeAsync with only the refresh token --
        // no accessTokenJti/accessTokenRemainingLifetime -- so the still-live access token
        // issued alongside it must still get blacklisted, sourced from the session row's own
        // persisted AccessTokenJti/AccessTokenExpiresAt rather than a caller-supplied value.
        var userId = await RegisterAndGetUserIdAsync("revoke-no-jti@example.com");
        var pair = await _service.IssueAsync(userId, "revoke-no-jti@example.com", [],
            "127.0.0.1", "Agent", "fp1");
        var realJti = _tokenService.ExtractJti(pair.AccessToken);

        (await _cache.ExistsAsync($"Bedrock:revoked:{realJti}")).Should().BeFalse();

        await _service.RevokeAsync(pair.RefreshToken, "127.0.0.1");

        (await _cache.ExistsAsync($"Bedrock:revoked:{realJti}")).Should().BeTrue(
            "revoking by refresh token alone must still blacklist the session's own access token");
    }

    // -------------------------------------------------------------------------
    // RevokeAllAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAllAsync_RevokesAllTokensAndSessions()
    {
        var userId = await RegisterAndGetUserIdAsync("revokeall@example.com");

        await _service.IssueAsync(userId, "revokeall@example.com", [], "127.0.0.1", "Agent", "fp1");
        await _service.IssueAsync(userId, "revokeall@example.com", [], "127.0.0.2", "Agent", "fp2");

        await _service.RevokeAllAsync(userId, "127.0.0.1");

        _context.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .Should().BeEmpty();

        _context.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .Should().BeEmpty();
    }

    public void Dispose()
    {
        _context.Dispose();
        _connection.Dispose();
    }
}
