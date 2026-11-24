using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Exceptions;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Crestacle.Sentinel.EntityFramework.Repositories;

internal sealed class RoleRepository(
    IAuthDbContext          context,
    ICurrentActor           actor,
    IPermissionCache        cache,
    ITenantContext          tenantContext,
    ILogger<RoleRepository> logger)
    : IRoleRepository
{
    public async Task<PagedResult<RoleDto>> GetAllWithPermissionsAsync(
        int page = 1, int pageSize = 50, string? search = null, CancellationToken ct = default)
    {
        var tenantId    = tenantContext.TenantId;
        var searchLower = search?.ToLowerInvariant();

        // Global/shared roles (TenantId == null, see Role.TenantId's own doc comment) must be
        // visible to a tenant-scoped caller too, not just when the caller itself has no tenant.
        var query = context.Roles
            .AsNoTracking()
            .Where(r => tenantId == null || r.TenantId == tenantId || r.TenantId == null)
            .Where(r => searchLower == null
                     || r.Name.ToLower().Contains(searchLower)
                     || (r.DisplayName != null && r.DisplayName.ToLower().Contains(searchLower)))
            .OrderBy(r => r.Type)
            .ThenBy(r => r.Name);

        var total = await query.CountAsync(ct);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new RoleDto(
                r.Id,
                r.Name,
                r.DisplayName,
                r.Type.ToString(),
                r.RequiresDualApproval,
                r.RolePermissions
                    .Where(rp => rp.RemovedOn == null
                              && (tenantId == null || rp.TenantId == tenantId || rp.TenantId == null))
                    .Select(rp => new PermissionDto(
                        rp.Permission.Id,
                        rp.Permission.Feature,
                        rp.Permission.Action,
                        rp.Permission.Group,
                        rp.Permission.Description))))
            .ToListAsync(ct);

        return new PagedResult<RoleDto>(items, page, pageSize, total);
    }

    public async Task<RoleDto?> GetByIdAsync(Guid roleId, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        return await context.Roles
            .AsNoTracking()
            .Where(r => r.Id == roleId && (tenantId == null || r.TenantId == tenantId || r.TenantId == null))
            .Select(r => new RoleDto(
                r.Id,
                r.Name,
                r.DisplayName,
                r.Type.ToString(),
                r.RequiresDualApproval,
                r.RolePermissions
                    .Where(rp => rp.RemovedOn == null
                              && (tenantId == null || rp.TenantId == tenantId || rp.TenantId == null))
                    .Select(rp => new PermissionDto(
                        rp.Permission.Id,
                        rp.Permission.Feature,
                        rp.Permission.Action,
                        rp.Permission.Group,
                        rp.Permission.Description))))
            .FirstOrDefaultAsync(ct);
    }

    public async Task<RoleType?> GetRoleTypeAsync(Guid roleId, CancellationToken ct = default)
        => await context.Roles
            .Where(r => r.Id == roleId)
            .Select(r => (RoleType?)r.Type)
            .FirstOrDefaultAsync(ct);

    public async Task<bool> RequiresDualApprovalAsync(Guid roleId, CancellationToken ct = default)
        => await context.Roles
            .Where(r => r.Id == roleId)
            .Select(r => r.RequiresDualApproval)
            .FirstOrDefaultAsync(ct);

    public async Task AddPermissionAsync(Guid roleId, string permissionId, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        // Fail fast with a meaningful error rather than letting the DB throw a FK violation.
        if (!await context.Permissions.AnyAsync(p => p.Id == permissionId, ct))
            throw new SentinelNotFoundException($"Permission '{permissionId}' does not exist.");

        var activeExists = await context.RolePermissions
            .AnyAsync(rp => rp.RoleId       == roleId
                         && rp.PermissionId == permissionId
                         && rp.RemovedOn    == null, ct);

        if (activeExists)
            return;

        var affectedIdentityIds = await AffectedIdentityIdsAsync(roleId, tenantId, ct);

        context.RolePermissions.Add(new RolePermission
        {
            RoleId       = roleId,
            PermissionId = permissionId,
            CreatedOn    = DateTime.UtcNow,
            TenantId     = tenantId,
        });

        context.AuditLog.Add(AuditEntry.Create(
            AuditAction.PermissionAssigned,
            $"{roleId}/{permissionId}",
            actor.IdentityId,
            actor.IpAddress,
            actor.UserAgent));

        try
        {
            await context.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            logger.LogWarning("Concurrency conflict adding permission {PermissionId} to role {RoleId}.", permissionId, roleId);
            throw new SentinelConcurrencyException(
                $"Concurrent write conflict on role {roleId}.", ex);
        }

        logger.LogInformation("Permission {PermissionId} added to role {RoleId}.", permissionId, roleId);

        foreach (var id in affectedIdentityIds)
            await cache.InvalidateUserAsync(id, ct);
    }

    public async Task RemovePermissionAsync(Guid roleId, string permissionId, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        var entry = await context.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId       == roleId
                                    && rp.PermissionId == permissionId
                                    && rp.RemovedOn    == null, ct);

        if (entry is null)
            return;

        var affectedIdentityIds = await AffectedIdentityIdsAsync(roleId, tenantId, ct);

        // Soft delete — preserve the row for audit continuity.
        entry.RemovedOn = DateTime.UtcNow;
        entry.RemovedBy = actor.IdentityId ?? "system";

        context.AuditLog.Add(AuditEntry.Create(
            AuditAction.PermissionRemoved,
            $"{roleId}/{permissionId}",
            actor.IdentityId,
            actor.IpAddress,
            actor.UserAgent));

        try
        {
            await context.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            logger.LogWarning("Concurrency conflict removing permission {PermissionId} from role {RoleId}.", permissionId, roleId);
            throw new SentinelConcurrencyException(
                $"Concurrent write conflict on role {roleId}.", ex);
        }

        logger.LogInformation("Permission {PermissionId} removed from role {RoleId}.", permissionId, roleId);

        foreach (var id in affectedIdentityIds)
            await cache.InvalidateUserAsync(id, ct);
    }

    private async Task<List<string>> AffectedIdentityIdsAsync(
        Guid      roleId,
        string?   tenantId,
        CancellationToken ct)
        => await context.UserRoles
            .Where(ur => ur.RoleId    == roleId
                      && ur.RemovedOn == null
                      && (tenantId   == null || ur.TenantId == tenantId))
            .Join(context.Users, ur => ur.UserId, u => u.Id, (_, u) => u.IdentityId)
            .ToListAsync(ct);
}
