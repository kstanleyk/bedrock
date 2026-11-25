using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Crestacle.Sentinel.EntityFramework.Repositories;

internal sealed class AuditRepository(IAuthDbContext context, ITenantContext tenantContext) : IAuditRepository
{
    public async Task<PagedResult<AuditEntryDto>> GetAsync(
        string?      actorIdentityId = null,
        AuditAction? action          = null,
        DateTime?    from            = null,
        DateTime?    to              = null,
        int          page            = 1,
        int          pageSize        = 50,
        CancellationToken ct         = default)
    {
        var tenantId = tenantContext.TenantId;

        var query = context.AuditLog
            .AsNoTracking()
            .Where(a => tenantId         == null || a.TenantId        == tenantId)
            .Where(a => actorIdentityId  == null || a.ActorIdentityId == actorIdentityId)
            .Where(a => action           == null || a.Action          == action)
            .Where(a => from             == null || a.CreatedOn       >= from)
            .Where(a => to               == null || a.CreatedOn       <= to)
            .OrderByDescending(a => a.CreatedOn);

        var total = await query.CountAsync(ct);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new AuditEntryDto(
                a.Id,
                a.Action.ToString(),
                a.EntityId,
                a.ActorIdentityId,
                a.ActorIp,
                a.ActorUserAgent,
                a.CreatedOn))
            .ToListAsync(ct);

        return new PagedResult<AuditEntryDto>(items, page, pageSize, total);
    }
}
