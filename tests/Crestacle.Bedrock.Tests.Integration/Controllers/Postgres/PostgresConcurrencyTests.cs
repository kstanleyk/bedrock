using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Tests.Integration.Infrastructure.Postgres;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers.Postgres;

/// <summary>
/// Regression coverage for docs/quality-roadmap.md D5: UserCredentialConfiguration /
/// SessionConfiguration / RefreshTokenConfiguration hardcode IsRowVersion(), which is a
/// genuine, DB-enforced optimistic-concurrency token only on SQL Server. On PostgreSQL, a
/// plain byte[] column has no database-level auto-update mechanism, so the "concurrency check"
/// was previously a silent no-op there -- two concurrent updates to the same row would both
/// succeed, the second silently overwriting the first, with no DbUpdateConcurrencyException
/// ever thrown. BedrockContext.OnModelCreating now auto-detects the Npgsql provider and maps
/// the real Postgres `xmin` system column as the concurrency token instead.
/// </summary>
[Collection("Postgres")]
[Trait("Provider", "Postgres")]
public sealed class PostgresConcurrencyTests
{
    [PostgresFact]
    public async Task UserCredential_ConcurrentUpdates_SecondSaveThrowsConcurrencyException()
    {
        using var db1 = PostgresDbContextFactory.Create();

        var credential = UserCredential.Create(Guid.NewGuid(), "pg-concurrency@example.com", new string('x', 60));
        db1.UserCredentials.Add(credential);
        await db1.SaveChangesAsync();

        // Two independent DbContexts loading the SAME row, simulating two concurrent requests.
        using var db2 = PostgresDbContextFactory.CreateWithoutResettingSchema();
        var copyInCtx1 = await db1.UserCredentials.FirstAsync(c => c.Id == credential.Id);
        var copyInCtx2 = await db2.UserCredentials.FirstAsync(c => c.Id == credential.Id);

        copyInCtx1.RecordFailedLogin(maxAttempts: 99, lockoutDuration: TimeSpan.FromMinutes(1));
        copyInCtx2.RecordFailedLogin(maxAttempts: 99, lockoutDuration: TimeSpan.FromMinutes(1));

        // First writer wins.
        await db1.SaveChangesAsync();

        // Second writer must be told its view of the row is stale -- the real, DB-enforced
        // concurrency check this fix exists to restore on PostgreSQL.
        var act = async () => await db2.SaveChangesAsync();
        await act.Should().ThrowAsync<DbUpdateConcurrencyException>(
            "two concurrent updates to the same row must not both silently succeed on PostgreSQL");
    }

    [PostgresFact]
    public async Task Session_ConcurrentUpdates_SecondSaveThrowsConcurrencyException()
    {
        using var db1 = PostgresDbContextFactory.Create();

        var session = Session.Create(
            Guid.NewGuid(), "hash", "fp", "1.2.3.4", "Agent/1.0",
            DateTime.UtcNow.AddDays(1));
        db1.Sessions.Add(session);
        await db1.SaveChangesAsync();

        using var db2 = PostgresDbContextFactory.CreateWithoutResettingSchema();
        var copyInCtx1 = await db1.Sessions.FirstAsync(s => s.Id == session.Id);
        var copyInCtx2 = await db2.Sessions.FirstAsync(s => s.Id == session.Id);

        copyInCtx1.Revoke("1.2.3.4");
        copyInCtx2.Revoke("5.6.7.8");

        await db1.SaveChangesAsync();

        var act = async () => await db2.SaveChangesAsync();
        await act.Should().ThrowAsync<DbUpdateConcurrencyException>();
    }

    /// <summary>
    /// Regression coverage for docs/quality-roadmap.md D3: RefreshTokenService.RefreshAsync had
    /// no concurrency guard on the token it rotates. Two concurrent requests presenting the SAME
    /// valid refresh token could both pass the IsActive check (loaded in separate DbContexts,
    /// mirroring two concurrent HTTP requests) and both rotate before either write landed --
    /// double-issuing new tokens and defeating single-use rotation semantics. This test exercises
    /// the same underlying DB mechanism RefreshAsync now relies on (RefreshToken.RowVersion ->
    /// Postgres xmin): BedrockUnitOfWork.SaveChangesAsync already translates the resulting
    /// DbUpdateConcurrencyException into BedrockConcurrencyException (409), so the losing
    /// request fails cleanly instead of silently succeeding.
    /// </summary>
    [PostgresFact]
    public async Task RefreshToken_ConcurrentRotations_SecondSaveThrowsConcurrencyException()
    {
        using var db1 = PostgresDbContextFactory.Create();

        var token = RefreshToken.Create(Guid.NewGuid(), "pg-refresh-race-hash", DateTime.UtcNow.AddDays(7), "1.2.3.4");
        db1.RefreshTokens.Add(token);
        await db1.SaveChangesAsync();

        using var db2 = PostgresDbContextFactory.CreateWithoutResettingSchema();
        var copyInCtx1 = await db1.RefreshTokens.FirstAsync(t => t.Id == token.Id);
        var copyInCtx2 = await db2.RefreshTokens.FirstAsync(t => t.Id == token.Id);

        // Simulates the two racing RefreshAsync calls each rotating the same token to a
        // different successor.
        copyInCtx1.Revoke("1.2.3.4", "successor-hash-a");
        copyInCtx2.Revoke("1.2.3.4", "successor-hash-b");

        await db1.SaveChangesAsync();

        var act = async () => await db2.SaveChangesAsync();
        await act.Should().ThrowAsync<DbUpdateConcurrencyException>(
            "two concurrent rotations of the same refresh token must not both silently succeed");
    }
}
