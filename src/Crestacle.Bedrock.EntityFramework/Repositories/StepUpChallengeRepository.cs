using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Crestacle.Bedrock.EntityFramework.Repositories;

internal sealed class StepUpChallengeRepository : IStepUpChallengeRepository
{
    private readonly BedrockContext _context;

    public StepUpChallengeRepository(BedrockContext context) => _context = context;

    public async Task<StepUpChallenge?> GetByIdAsync(Guid id, CancellationToken ct = default)
        => await _context.StepUpChallenges.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id, ct);

    public async Task AddAsync(StepUpChallenge challenge, CancellationToken ct = default)
        => await _context.StepUpChallenges.AddAsync(challenge, ct);

    public async Task UpdateAsync(StepUpChallenge challenge, CancellationToken ct = default)
    {
        var tracked = _context.ChangeTracker.Entries<StepUpChallenge>()
            .FirstOrDefault(e => e.Entity.Id == challenge.Id);
        if (tracked is not null)
        {
            tracked.CurrentValues.SetValues(challenge);
            return;
        }

        // Same fix as SessionRepository/CredentialRepository.UpdateAsync (see their longer
        // comment for the full explanation): GetByIdAsync reads AsNoTracking, so a blanket
        // `_context.StepUpChallenges.Update(challenge)` attach on a genuinely fresh scope
        // loses the row's real concurrency-token (RowVersion/xmin) value and always reports
        // "0 rows affected" (DbUpdateConcurrencyException) on every real call, not just under
        // contention -- the same bug confirmed live against Postgres for RefreshTokenRepository
        // during the pentest-hardening completion smoke pass; this repository had the
        // identical gap. Without this fix, RequiresStepUpAttribute's catch for
        // BedrockConcurrencyException (added for the legitimate contention case) would
        // incorrectly fire on every first, uncontended use too, reporting "already been used"
        // for a challenge that was never actually consumed before. A tracked stub loaded by
        // primary key first captures the real, current token value before
        // CurrentValues.SetValues overlays the caller's own field values onto it.
        var trackedStub = await _context.StepUpChallenges.FindAsync([challenge.Id], ct)
            ?? throw new InvalidOperationException($"StepUpChallenge {challenge.Id} not found for update.");
        _context.Entry(trackedStub).CurrentValues.SetValues(challenge);
    }

    public async Task ExpireStaleAsync(CancellationToken ct = default)
        => await _context.StepUpChallenges
            .Where(c => c.ExpiresAt < DateTime.UtcNow)
            .ExecuteDeleteAsync(ct);
}
