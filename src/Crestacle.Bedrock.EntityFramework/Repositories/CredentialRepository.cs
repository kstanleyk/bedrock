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
        // xmin concurrency token -- an AsNoTracking-materialized object never carries
        // one as a shadow property -- so the generated `WHERE ... AND xmin = @p` always
        // compares against the CLR default (0), and since Postgres transaction ids are
        // never 0, the UPDATE always reports "0 rows affected"
        // (DbUpdateConcurrencyException) on every real, separate-request call. Loading a
        // genuinely tracked stub by primary key first captures the row's real, current
        // xmin before CurrentValues.SetValues overlays the caller's own field values
        // onto it, so the concurrency check is correct regardless of how the caller
        // originally obtained `credential`.
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
