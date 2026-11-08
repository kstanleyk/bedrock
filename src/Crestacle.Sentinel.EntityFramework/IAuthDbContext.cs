using Crestacle.Sentinel.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Crestacle.Sentinel.EntityFramework;

/// <summary>
/// Implemented by the app's DbContext to expose all Sentinel auth tables.
/// </summary>
public interface IAuthDbContext
{
    DbSet<User>               Users               { get; }
    DbSet<Role>               Roles               { get; }
    DbSet<Permission>         Permissions         { get; }
    DbSet<UserRole>           UserRoles           { get; }
    DbSet<RolePermission>     RolePermissions     { get; }
    DbSet<AuditEntry>         AuditLog            { get; }
    DbSet<PermissionConflict> PermissionConflicts { get; }
    DbSet<PendingAssignment>  PendingAssignments  { get; }

    DatabaseFacade Database { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
