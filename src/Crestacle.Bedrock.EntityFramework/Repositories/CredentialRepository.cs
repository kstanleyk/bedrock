using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Crestacle.Bedrock.EntityFramework.Repositories;

internal sealed class CredentialRepository : ICredentialRepository
{
    private readonly BedrockContext _context;

    public CredentialRepository(BedrockContext context) => _context = context;

    public async Task<UserCredential?> GetByUserIdAsync(Guid userId, CancellationToken ct = default)
        => await _context.UserCredentials.AsNoTracking()
            .FirstOrDefaultAsync(c => c.UserId == userId, ct);

    public async Task<UserCredential?> GetByEmailAsync(string email, CancellationToken ct = default)
        => await _context.UserCredentials.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Email == email, ct);

    public async Task AddAsync(UserCredential credential, CancellationToken ct = default)
        => await _context.UserCredentials.AddAsync(credential, ct);

    public async Task UpdateAsync(UserCredential credential, CancellationToken ct = default)
    {
        var tracked = _context.ChangeTracker.Entries<UserCredential>()
            .FirstOrDefault(e => e.Entity.Id == credential.Id);
        if (tracked is not null)
        {
            tracked.CurrentValues.SetValues(credential);
            return;
        }

        // No tracked entry exists in this DbContext scope -- true whenever this method
        // is called against a genuinely fresh request/scope (this repository's own
        // GetByUserIdAsync/GetByEmailAsync both read AsNoTracking by design). A blanket
        // `_context.UserCredentials.Update(credential)` attach here loses the row's real
        // concurrency-token value -- an AsNoTracking-materialized object's original value
        // isn't retained once the caller mutates the entity in memory -- so the generated
        // concurrency-check WHERE clause would compare against a stale or default value
        // and always report "0 rows affected" (DbUpdateConcurrencyException) on every real,
        // separate-request call. Loading a genuinely tracked stub by primary key first
        // captures the row's real, current concurrency-token value before
        // CurrentValues.SetValues overlays the caller's own field values onto it, so the
        // comparison is against the real stored value regardless of how the caller
        // originally obtained `credential`.
        //
        // The actual token differs by provider (docs/quality-roadmap.md D5, fixed): SQL
        // Server uses UserCredentialConfiguration's IsRowVersion() byte[] RowVersion column
        // directly (its native rowversion/timestamp type auto-increments on every write).
        // PostgreSQL has no equivalent for a plain byte[] column, so BedrockContext
        // .OnModelCreating auto-detects the Npgsql provider and maps the real `xmin` system
        // column (which DOES change on every UPDATE) as the concurrency token instead,
        // ignoring RowVersion entirely in that case. Either way, this method's job is the
        // same: make sure the save compares against the row's actual current token, not a
        // stale or default one.
        var trackedStub = await _context.UserCredentials.FindAsync([credential.Id], ct)
            ?? throw new InvalidOperationException($"UserCredential {credential.Id} not found for update.");
        _context.Entry(trackedStub).CurrentValues.SetValues(credential);
    }

    public async Task<bool> ExistsByEmailAsync(string email, CancellationToken ct = default)
        => await _context.UserCredentials.AnyAsync(c => c.Email == email, ct);

    public async Task<PagedResult<CredentialSummary>> GetPagedAsync(
        int page, int pageSize, CancellationToken ct = default)
    {
        var query = _context.UserCredentials.AsNoTracking();
        var totalCount = await query.CountAsync(ct);
        var items = await query
            .OrderBy(c => c.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(c => new CredentialSummary(
                c.UserId, c.Email, c.Status, c.EmailConfirmed, c.MfaEnabled,
                c.LockoutEnd, c.CreatedAt))
            .ToListAsync(ct);
        return new PagedResult<CredentialSummary>(items, totalCount, page, pageSize);
    }
}
