namespace Crestacle.Sentinel.Core.Entities;

/// <summary>
/// A Sentinel RBAC identity, keyed on <see cref="IdentityId"/> -- the bridge key to the
/// external auth system's own user record (Bedrock, in this stack). <see cref="IdentityId"/>
/// and <see cref="Email"/> are globally unique by design, not tenant-scoped: a User row
/// represents one real identity, and multi-tenancy is modeled as that same identity holding
/// separate <see cref="UserRole"/> memberships per tenant -- not as a separate account per
/// tenant. This is why <see cref="Role.Name"/> is tenant-scoped-unique instead: role labels are
/// organizational and expected to collide across tenants ("Admin" in two different tenants),
/// but a person's identity is not duplicated per tenant.
/// </summary>
public sealed class User : Entity<Guid>
{
    public string  IdentityId { get; private set; } = string.Empty;
    public string  Email      { get; private set; } = string.Empty;
    public string? FullName   { get; private set; }
    public string? Phone      { get; private set; }

    /// <summary>Tenant this user belongs to. Null in single-tenant deployments.</summary>
    public string? TenantId   { get; private set; }

    public DateTime CreatedOn { get; private set; }

    public ICollection<UserRole> UserRoles { get; private set; } = [];

    private User() { }

    public static User Create(
        string  identityId,
        string  email,
        string? fullName = null,
        string? phone    = null,
        string? tenantId = null)
        => new()
        {
            Id         = Guid.NewGuid(),
            IdentityId = identityId,
            Email      = email,
            FullName   = fullName,
            Phone      = phone,
            TenantId   = tenantId,
            CreatedOn  = DateTime.UtcNow,
        };
}
