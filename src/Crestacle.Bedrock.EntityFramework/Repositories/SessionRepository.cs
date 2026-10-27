using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Crestacle.Bedrock.EntityFramework.Repositories;

internal sealed class SessionRepository : ISessionRepository
{
    private readonly BedrockContext _context;

    public SessionRepository(BedrockContext context) => _context = context;

    public async Task<Session?> GetByIdAsync(Guid id, CancellationToken ct = default)
        => await _context.Sessions.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == id, ct);

    public async Task<Session?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default)
        => await _context.Sessions.AsNoTracking()
            .FirstOrDefaultAsync(s => s.TokenHash == tokenHash, ct);

    public async Task<IReadOnlyList<Session>> GetActiveByUserAsync(
        Guid userId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return await _context.Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderByDescending(s => s.LastActivityAt)
            .ToListAsync(ct);
    }

    public async Task AddAsync(Session session, CancellationToken ct = default)
        => await _context.Sessions.AddAsync(session, ct);

    public async Task UpdateAsync(Session session, CancellationToken ct = default)
    {
        var tracked = _context.ChangeTracker.Entries<Session>()
            .FirstOrDefault(e => e.Entity.Id == session.Id);
        if (tracked is not null)
        {
            tracked.CurrentValues.SetValues(session);
            return;
        }

        // Same fix as CredentialRepository.UpdateAsync (this class's own sibling) --
        // GetByIdAsync/GetByTokenHashAsync both read AsNoTracking, so a blanket
        // `_context.Sessions.Update(session)` attach on a genuinely fresh scope loses
        // the row's real xmin concurrency token, making the concurrency check always
        // compare against the CLR default (0) and always report "0 rows affected." A
        // tracked stub loaded by primary key first captures the real xmin before
        // CurrentValues.SetValues overlays the caller's own field values onto it.
        var trackedStub = await _context.Sessions.FindAsync([session.Id], ct)
            ?? throw new InvalidOperationException($"Session {session.Id} not found for update.");
        _context.Entry(trackedStub).CurrentValues.SetValues(session);
    }

    public async Task RevokeAllForUserAsync(Guid userId, string byIp, CancellationToken ct = default)
        => await _context.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .ExecuteUpdateAsync(calls => calls
                .SetProperty(s => s.RevokedAt, DateTime.UtcNow)
                .SetProperty(s => s.RevokedByIp, byIp), ct);

    public async Task<int> CountActiveForUserAsync(Guid userId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return await _context.Sessions
            .CountAsync(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now, ct);
    }

    public async Task<Session?> GetOldestActiveForUserAsync(Guid userId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return await _context.Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderBy(s => s.CreatedAt)
            .FirstOrDefaultAsync(ct);
    }
}
