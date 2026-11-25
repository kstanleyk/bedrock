using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Crestacle.Bedrock.EntityFramework.Repositories;

internal sealed class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly BedrockContext _context;

    public RefreshTokenRepository(BedrockContext context) => _context = context;

    public async Task<RefreshToken?> GetByHashAsync(string tokenHash, CancellationToken ct = default)
        => await _context.RefreshTokens.AsNoTracking()
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);

    public async Task AddAsync(RefreshToken token, CancellationToken ct = default)
        => await _context.RefreshTokens.AddAsync(token, ct);

    public async Task UpdateAsync(RefreshToken token, CancellationToken ct = default)
    {
        var tracked = _context.ChangeTracker.Entries<RefreshToken>()
            .FirstOrDefault(e => e.Entity.Id == token.Id);
        if (tracked is not null)
        {
            tracked.CurrentValues.SetValues(token);
            return;
        }

        // Same fix as SessionRepository/CredentialRepository.UpdateAsync (see their longer
        // comment for the full explanation): GetByHashAsync reads AsNoTracking, so a blanket
        // `_context.RefreshTokens.Update(token)` attach on a genuinely fresh scope loses the
        // row's real concurrency-token (RowVersion/xmin) value and always reports "0 rows
        // affected" (DbUpdateConcurrencyException) on every real call, not just under
        // contention -- confirmed live against Postgres during the pentest-hardening
        // completion smoke pass, where every refresh deterministically 409'd. A tracked stub
        // loaded by primary key first captures the real, current token value before
        // CurrentValues.SetValues overlays the caller's own field values onto it.
        var trackedStub = await _context.RefreshTokens.FindAsync([token.Id], ct)
            ?? throw new InvalidOperationException($"RefreshToken {token.Id} not found for update.");
        _context.Entry(trackedStub).CurrentValues.SetValues(token);
    }

    public async Task RevokeAllForUserAsync(Guid userId, string byIp, CancellationToken ct = default)
        => await _context.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.RevokedAt, DateTime.UtcNow)
                .SetProperty(t => t.RevokedByIp, byIp), ct);

    public async Task<int> CountActiveForUserAsync(Guid userId, CancellationToken ct = default)
        => await _context.RefreshTokens
            .CountAsync(t => t.UserId == userId && t.RevokedAt == null && t.ExpiresAt > DateTime.UtcNow, ct);
}
