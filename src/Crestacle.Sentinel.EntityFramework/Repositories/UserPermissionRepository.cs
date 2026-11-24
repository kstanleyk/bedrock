using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Crestacle.Sentinel.EntityFramework.Repositories;

internal sealed class UserPermissionRepository(
    IAuthDbContext                      context,
    IPermissionCache                    cache,
    ITenantContext                      tenantContext,
    ILogger<UserPermissionRepository>   logger)
    : IUserPermissionRepository
{
    public async Task<HashSet<string>> GetPermissionsForUserAsync(string identityId, CancellationToken ct = default)
    {
        var cached = await cache.GetAsync(identityId, ct);
        if (cached is not null)
        {
            logger.LogDebug("Permission cache hit for {IdentityId} ({Count} permissions).", identityId, cached.Count);
            return cached;
        }

        logger.LogDebug("Permission cache miss for {IdentityId} — loading from database.", identityId);

        var tenantId = tenantContext.TenantId;
        var now      = DateTime.UtcNow;

        var userId = await context.Users
            .Where(u => u.IdentityId == identityId)
            .Where(u => tenantId == null || u.TenantId == tenantId)
            .Select(u => u.Id)
            .FirstOrDefaultAsync(ct);

        if (userId == default)
            return [];

        // Collect directly-assigned active role IDs.
        var directRoleIds = await context.UserRoles
            .Where(ur => ur.UserId    == userId
                      && ur.RemovedOn == null
                      && (ur.ExpiresOn == null || ur.ExpiresOn > now)
                      && (tenantId    == null  || ur.TenantId  == tenantId))
            .Select(ur => ur.RoleId)
            .ToListAsync(ct);

        // Expand with inherited roles from the hierarchy.
        var allRoleIds = await ResolveHierarchyAsync(directRoleIds, tenantId, ct);

        // Resolve permissions for all collected roles (active assignments only). A global
        // RolePermission row (TenantId == null, see Role.TenantId's own doc comment for the
        // same "global/shared" concept) must always be visible to a tenant-scoped caller too --
        // not just when the CALLER has no tenant. Without the trailing `|| rp.TenantId == null`,
        // every global role's permissions silently resolved to nothing for any tenant-scoped
        // user, breaking the seeded-roles bootstrap this library ships by default.
        var permissions = await context.RolePermissions
            .Where(rp => allRoleIds.Contains(rp.RoleId)
                      && rp.RemovedOn == null
                      && (tenantId == null || rp.TenantId == tenantId || rp.TenantId == null))
            .Select(rp => rp.Permission.Id)
            .Distinct()
            .ToListAsync(ct);

        var result = permissions.ToHashSet();
        logger.LogDebug("Loaded {Count} permissions for {IdentityId} — storing in cache.", result.Count, identityId);
        await cache.SetAsync(identityId, result, ct);
        return result;
    }

    // Iteratively walks up the role hierarchy, bounded to MaxDepth to prevent infinite loops.
    private async Task<HashSet<Guid>> ResolveHierarchyAsync(
        IEnumerable<Guid> directRoleIds,
        string?           tenantId,
        CancellationToken ct)
    {
        const int MaxDepth = 10;

        var allIds    = new HashSet<Guid>(directRoleIds);
        var toProcess = new Queue<Guid>(directRoleIds);

        for (var depth = 0; depth < MaxDepth && toProcess.Count > 0; depth++)
        {
            var batch = toProcess.ToList();
            toProcess.Clear();

            var parentIds = await context.Roles
                .Where(r => batch.Contains(r.Id) && r.ParentRoleId.HasValue)
                .Where(r => tenantId == null || r.TenantId == tenantId || r.TenantId == null)
                .Select(r => r.ParentRoleId!.Value)
                .ToListAsync(ct);

            foreach (var pid in parentIds)
                if (allIds.Add(pid))
                    toProcess.Enqueue(pid);
        }

        return allIds;
    }

    public void Dispose() { }
}
