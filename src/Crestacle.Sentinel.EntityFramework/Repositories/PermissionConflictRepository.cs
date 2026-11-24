using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Crestacle.Sentinel.EntityFramework.Repositories;

internal sealed class PermissionConflictRepository(
    IAuthDbContext context,
    ICurrentActor  actor,
    ITenantContext tenantContext)
    : IPermissionConflictRepository
{
    public async Task<IReadOnlyList<PermissionConflictDto>> GetAllAsync(CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        return await context.PermissionConflicts
            .AsNoTracking()
            .Where(pc => tenantId == null || pc.TenantId == tenantId || pc.TenantId == null)
            .OrderBy(pc => pc.PermissionIdA)
            .Select(pc => new PermissionConflictDto(pc.Id, pc.PermissionIdA, pc.PermissionIdB, pc.CreatedBy, pc.CreatedOn))
            .ToListAsync(ct);
    }

    public async Task<bool> HasConflictAsync(Guid roleId, string newPermissionId, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        // Get all permission IDs currently active on this role. Must also see a global role's
        // global RolePermission rows from a tenant-scoped caller (same fix as
        // UserPermissionRepository/RoleRepository) -- otherwise SoD conflict detection silently
        // sees an empty permission set for any global role and never flags a real conflict.
        var existing = await context.RolePermissions
            .Where(rp => rp.RoleId    == roleId
                      && rp.RemovedOn == null
                      && (tenantId == null || rp.TenantId == tenantId || rp.TenantId == null))
            .Select(rp => rp.PermissionId)
            .ToListAsync(ct);

        if (existing.Count == 0)
            return false;

        // Check if any (existing, new) pair appears in the conflict table.
        return await context.PermissionConflicts
            .Where(pc => tenantId == null || pc.TenantId == tenantId || pc.TenantId == null)
            .AnyAsync(pc =>
                (pc.PermissionIdA == newPermissionId && existing.Contains(pc.PermissionIdB)) ||
                (pc.PermissionIdB == newPermissionId && existing.Contains(pc.PermissionIdA)), ct);
    }

    public async Task AddConflictAsync(string permissionIdA, string permissionIdB, CancellationToken ct = default)
    {
        var conflict = PermissionConflict.Create(
            permissionIdA,
            permissionIdB,
            actor.IdentityId ?? "system",
            tenantContext.TenantId);

        context.PermissionConflicts.Add(conflict);
        await context.SaveChangesAsync(ct);
    }

    public async Task RemoveConflictAsync(Guid conflictId, CancellationToken ct = default)
    {
        var entry = await context.PermissionConflicts.FindAsync([conflictId], ct);
        if (entry is null)
            return;

        context.PermissionConflicts.Remove(entry);
        await context.SaveChangesAsync(ct);
    }
}
