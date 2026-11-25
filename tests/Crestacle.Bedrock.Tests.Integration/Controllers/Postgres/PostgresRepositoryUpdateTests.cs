using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Tests.Integration.Infrastructure.Postgres;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers.Postgres;

/// <summary>
/// Regression coverage discovered during the pentest-hardening-plan.md completion smoke pass:
/// <see cref="PostgresConcurrencyTests"/> proves the underlying Postgres `xmin` concurrency
/// mechanism works, but loads entities via a tracked DbContext query directly
/// (<c>db.RefreshTokens.FirstAsync(...)</c>), never going through the actual production code
/// path -- <c>RefreshTokenRepository.GetByHashAsync</c>/<c>StepUpChallengeRepository.GetByIdAsync</c>
/// (both <c>AsNoTracking</c>) followed by the repository's own <c>UpdateAsync</c>. That path had a
/// real, deterministic bug: re-attaching a never-tracked entity via a blanket
/// <c>_context.RefreshTokens.Update(token)</c> compares the shadow <c>xmin</c> concurrency token
/// against its CLR default rather than the row's real value, so EVERY first, uncontended update
/// failed with <see cref="Crestacle.Bedrock.Core.Exceptions.BedrockConcurrencyException"/> --
/// confirmed live against a real Postgres instance (not SQLite), where
/// <c>POST auth/refresh</c> 409'd on literally every call. Fixed by applying the same
/// tracked-stub-via-FindAsync pattern <c>SessionRepository</c>/<c>CredentialRepository</c>
/// already used. These tests exercise the real repository methods directly (not raw DbContext
/// queries) so this specific regression can't silently return.
/// </summary>
[Collection("Postgres")]
[Trait("Provider", "Postgres")]
public sealed class PostgresRepositoryUpdateTests
{
    [PostgresFact]
    public async Task RefreshTokenRepository_UpdateAfterAsNoTrackingFetch_SingleUncontendedUpdateSucceeds()
    {
        using var server = new PostgresBedrockTestServer();
        var repo = server.Host.Services.GetRequiredService<IRefreshTokenRepository>();

        var token = RefreshToken.Create(Guid.NewGuid(), "pg-repo-update-hash", DateTime.UtcNow.AddDays(7), "1.2.3.4");
        await repo.AddAsync(token);
        await server.DbContext.SaveChangesAsync();
        server.DbContext.ChangeTracker.Clear();

        // The real production path: a fresh, AsNoTracking fetch (as RefreshTokenService.RefreshAsync
        // does via GetByHashAsync), mutate, then UpdateAsync -- no contention, no second writer.
        var fetched = await repo.GetByHashAsync("pg-repo-update-hash");
        fetched!.Revoke("1.2.3.4", "successor-hash");

        var act = async () =>
        {
            await repo.UpdateAsync(fetched);
            await server.DbContext.SaveChangesAsync();
        };

        await act.Should().NotThrowAsync(
            "a single, uncontended update through the repository's real GetByHashAsync+UpdateAsync " +
            "path must succeed -- it must not compare the shadow concurrency token against a stale " +
            "default value just because the entity was fetched AsNoTracking");
    }

    [PostgresFact]
    public async Task StepUpChallengeRepository_UpdateAfterAsNoTrackingFetch_SingleUncontendedUpdateSucceeds()
    {
        using var server = new PostgresBedrockTestServer();
        var repo = server.Host.Services.GetRequiredService<IStepUpChallengeRepository>();

        var challenge = StepUpChallenge.Create(
            Guid.NewGuid(), MfaMethod.Totp, codeHash: null, "1.2.3.4", DateTime.UtcNow.AddMinutes(5));
        await repo.AddAsync(challenge);
        await server.DbContext.SaveChangesAsync();
        server.DbContext.ChangeTracker.Clear();

        // The real production path: a fresh, AsNoTracking fetch (as RequiresStepUpAttribute does
        // via GetByIdAsync), mutate, then UpdateAsync -- no contention, no second writer.
        var fetched = await repo.GetByIdAsync(challenge.Id);
        fetched!.MarkUsed();

        var act = async () =>
        {
            await repo.UpdateAsync(fetched);
            await server.DbContext.SaveChangesAsync();
        };

        await act.Should().NotThrowAsync(
            "a single, uncontended update through the repository's real GetByIdAsync+UpdateAsync " +
            "path must succeed -- without this fix, a first-time, never-contended step-up " +
            "consumption would be wrongly reported as \"already used\"");
    }
}
