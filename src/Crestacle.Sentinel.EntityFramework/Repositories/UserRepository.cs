using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Events;
using Crestacle.Sentinel.Core.Exceptions;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Crestacle.Sentinel.EntityFramework.Repositories;

internal sealed class UserRepository(
    IAuthDbContext              context,
    ICurrentActor               actor,
    IPermissionCache            cache,
    ITenantContext              tenantContext,
    ISentinelEventPublisher     eventPublisher,
    ILogger<UserRepository>     logger)
    : IUserRepository
{
    public async Task<PagedResult<UserDto>> GetAllWithRolesAsync(
        int page = 1, int pageSize = 50, string? search = null, CancellationToken ct = default)
    {
        var tenantId    = tenantContext.TenantId;
        var searchLower = search?.ToLowerInvariant();

        var query = context.Users
            .AsNoTracking()
            .Where(u => tenantId == null || u.TenantId == tenantId)
            .Where(u => searchLower == null
                     || u.Email.ToLower().Contains(searchLower)
                     || (u.FullName != null && u.FullName.ToLower().Contains(searchLower)))
            .OrderBy(u => u.FullName);

        var total = await query.CountAsync(ct);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new UserDto(
                u.Id,
                u.IdentityId,
                u.Email,
                u.FullName,
                u.Phone,
                u.UserRoles
                    .Where(ur => ur.RemovedOn == null
                              && (ur.ExpiresOn == null || ur.ExpiresOn > DateTime.UtcNow)
                              && (tenantId    == null  || ur.TenantId  == tenantId))
                    .Select(ur => new RoleSummaryDto(
                        ur.Role.Id, ur.Role.Name, ur.Role.DisplayName, ur.Role.Type.ToString(), ur.ExpiresOn))))
            .ToListAsync(ct);

        return new PagedResult<UserDto>(items, page, pageSize, total);
    }

    public async Task<UserDto?> GetByIdAsync(Guid userId, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        return await context.Users
            .AsNoTracking()
            .Where(u => u.Id == userId && (tenantId == null || u.TenantId == tenantId))
            .Select(u => new UserDto(
                u.Id,
                u.IdentityId,
                u.Email,
                u.FullName,
                u.Phone,
                u.UserRoles
                    .Where(ur => ur.RemovedOn == null
                              && (ur.ExpiresOn == null || ur.ExpiresOn > DateTime.UtcNow)
                              && (tenantId    == null  || ur.TenantId  == tenantId))
                    .Select(ur => new RoleSummaryDto(
                        ur.Role.Id, ur.Role.Name, ur.Role.DisplayName, ur.Role.Type.ToString(), ur.ExpiresOn))))
            .FirstOrDefaultAsync(ct);
    }

    public async Task<UserDto?> GetByIdentityIdAsync(string identityId, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        return await context.Users
            .AsNoTracking()
            .Where(u => u.IdentityId == identityId && (tenantId == null || u.TenantId == tenantId))
            .Select(u => new UserDto(
                u.Id,
                u.IdentityId,
                u.Email,
                u.FullName,
                u.Phone,
                u.UserRoles
                    .Where(ur => ur.RemovedOn == null
                              && (ur.ExpiresOn == null || ur.ExpiresOn > DateTime.UtcNow)
                              && (tenantId    == null  || ur.TenantId  == tenantId))
                    .Select(ur => new RoleSummaryDto(
                        ur.Role.Id, ur.Role.Name, ur.Role.DisplayName, ur.Role.Type.ToString(), ur.ExpiresOn))))
            .FirstOrDefaultAsync(ct);
    }

    public async Task<string?> GetIdentityIdAsync(Guid userId, CancellationToken ct = default)
        => await context.Users
            .Where(u => u.Id == userId)
            .Select(u => u.IdentityId)
            .FirstOrDefaultAsync(ct);

    public async Task AddRoleAsync(
        Guid      userId,
        Guid      roleId,
        DateTime? expiresOn = null,
        CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        // Ownership check: roleId must actually belong to the acting tenant (or be a global/
        // shared role, TenantId == null) before it can be attached to any user. Without this,
        // a tenant-A actor holding only User.Update could attach an arbitrary tenant-B-only
        // role (by guessing/enumerating its GUID) to a tenant-A user -- previously harmless
        // only by accident, because the global-role permission-resolution bug meant a
        // misassigned cross-tenant role resolved to no permissions either way; now that that
        // bug is fixed (global roles correctly grant permissions), an unchecked cross-tenant
        // assignment would be a real privilege-escalation path.
        var roleExists = await context.Roles
            .AnyAsync(r => r.Id == roleId && (tenantId == null || r.TenantId == tenantId || r.TenantId == null), ct);
        if (!roleExists)
            throw new SentinelNotFoundException($"Role {roleId} not found.");

        // Active = not removed and not expired.
        var activeExists = await context.UserRoles
            .AnyAsync(ur => ur.UserId    == userId
                         && ur.RoleId    == roleId
                         && ur.RemovedOn == null
                         && (ur.ExpiresOn == null || ur.ExpiresOn > DateTime.UtcNow), ct);

        if (activeExists)
        {
            logger.LogDebug("Role {RoleId} already active for user {UserId} — skipping assignment.", roleId, userId);
            return;
        }

        var identityId = await GetIdentityIdAsync(userId, ct);

        context.UserRoles.Add(new UserRole
        {
            Id        = Guid.NewGuid(),
            UserId    = userId,
            RoleId    = roleId,
            CreatedOn = DateTime.UtcNow,
            ExpiresOn = expiresOn,
            TenantId  = tenantId,
        });

        context.AuditLog.Add(AuditEntry.Create(
            AuditAction.RoleAssigned,
            $"{userId}/{roleId}",
            actor.IdentityId,
            actor.IpAddress,
            actor.UserAgent));

        await context.SaveChangesAsync(ct);

        logger.LogInformation("Role {RoleId} assigned to user {UserId} (expiresOn={ExpiresOn}).", roleId, userId, expiresOn);

        if (identityId is not null)
            await cache.InvalidateUserAsync(identityId, ct);

        await eventPublisher.PublishAsync(
            new RoleAssignedEvent(userId, identityId, roleId, tenantId, expiresOn, DateTime.UtcNow), ct);
    }

    public async Task RemoveRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;

        var entry = await context.UserRoles
            .FirstOrDefaultAsync(ur => ur.UserId    == userId
                                    && ur.RoleId    == roleId
                                    && ur.RemovedOn == null
                                    && (tenantId    == null || ur.TenantId == tenantId), ct);

        if (entry is null)
        {
            logger.LogDebug("Active role {RoleId} not found for user {UserId} — nothing to remove.", roleId, userId);
            return;
        }

        var identityId = await GetIdentityIdAsync(userId, ct);

        // Soft delete — preserve the row for audit continuity.
        entry.RemovedOn = DateTime.UtcNow;
        entry.RemovedBy = actor.IdentityId ?? "system";

        context.AuditLog.Add(AuditEntry.Create(
            AuditAction.RoleRemoved,
            $"{userId}/{roleId}",
            actor.IdentityId,
            actor.IpAddress,
            actor.UserAgent));

        await context.SaveChangesAsync(ct);

        logger.LogInformation("Role {RoleId} removed from user {UserId}.", roleId, userId);

        if (identityId is not null)
            await cache.InvalidateUserAsync(identityId, ct);

        await eventPublisher.PublishAsync(
            new RoleRemovedEvent(userId, identityId, roleId, tenantId, DateTime.UtcNow), ct);
    }
}
