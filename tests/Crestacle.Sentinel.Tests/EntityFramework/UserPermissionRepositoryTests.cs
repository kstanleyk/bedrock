using Crestacle.Sentinel.Core.Authorization;
using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Interfaces;
using Crestacle.Sentinel.EntityFramework.Repositories;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSubstitute;

// NullTenantContext for tests — single-tenant, no filtering.

namespace Crestacle.Sentinel.Tests.EntityFramework;

public sealed class UserPermissionRepositoryTests
{
    private static TestAuthDbContext BuildContext()
    {
        var opts = new DbContextOptionsBuilder<TestAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new TestAuthDbContext(opts);
    }

    // Always returns a cache miss — forces DB reads in every test.
    private static IPermissionCache NullCache()
    {
        var cache = Substitute.For<IPermissionCache>();
        cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
             .Returns((HashSet<string>?)null);
        return cache;
    }

    private static ILogger<UserPermissionRepository> NullLog()
        => Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance
               .CreateLogger<UserPermissionRepository>();

    // Single-tenant context — no tenant filtering.
    private static ITenantContext NullTenant()
    {
        var ctx = Substitute.For<ITenantContext>();
        ctx.TenantId.Returns((string?)null);
        return ctx;
    }

    [Fact]
    public async Task GetPermissionsForUserAsync_ReturnsPermissions_ForKnownUser()
    {
        await using var ctx = BuildContext();

        var user = User.Create("identity-1", "user@test.com");
        var role = Role.Create("Admin", "Administrator", RoleType.Default);
        var perm = Permission.Create(new AppPermission("Invoice", "Read", "Finance", "Read invoices"));

        ctx.Users.Add(user);
        ctx.Roles.Add(role);
        ctx.Permissions.Add(perm);
        ctx.UserRoles.Add(new UserRole { Id = Guid.NewGuid(), UserId = user.Id, RoleId = role.Id, CreatedOn = DateTime.UtcNow });
        ctx.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionId = perm.Id, CreatedOn = DateTime.UtcNow });
        await ctx.SaveChangesAsync();

        var repo = new UserPermissionRepository(ctx, NullCache(), NullTenant(), NullLog());
        var result = await repo.GetPermissionsForUserAsync("identity-1");

        result.Should().ContainSingle().Which.Should().Be("Permission.Invoice.Read");
    }

    // Tenant-scoped context — matches a real multi-tenant deployment.
    private static ITenantContext TenantScoped(string tenantId)
    {
        var ctx = Substitute.For<ITenantContext>();
        ctx.TenantId.Returns(tenantId);
        return ctx;
    }

    [Fact]
    public async Task GetPermissionsForUserAsync_GlobalRoleViaTenantScopedUser_StillResolvesItsPermissions()
    {
        // The library's own supported bootstrap (SentinelSeeder.SeedRolesAsync) creates roles
        // and RolePermission rows with TenantId left null (global/shared, per Role.TenantId's
        // own doc comment) — but the user themselves, and their UserRole assignment, DO belong
        // to a real tenant, exactly as a real multi-tenant deployment using the seeded roles
        // would have. A tenant-scoped caller must still see the global role's permissions.
        await using var ctx = BuildContext();

        const string tenantId = "tenant-a";
        var user = User.Create("identity-tenant-a", "user@tenant-a.test", tenantId: tenantId);
        var role = Role.Create("Admin", "Administrator", RoleType.Default, tenantId: null); // global
        var perm = Permission.Create(new AppPermission("Invoice", "Read", "Finance", "Read invoices"));

        ctx.Users.Add(user);
        ctx.Roles.Add(role);
        ctx.Permissions.Add(perm);
        ctx.UserRoles.Add(new UserRole
        {
            Id = Guid.NewGuid(), UserId = user.Id, RoleId = role.Id,
            TenantId = tenantId, CreatedOn = DateTime.UtcNow,
        });
        ctx.RolePermissions.Add(new RolePermission
        {
            RoleId = role.Id, PermissionId = perm.Id,
            TenantId = null, CreatedOn = DateTime.UtcNow,
        });
        await ctx.SaveChangesAsync();

        var repo = new UserPermissionRepository(ctx, NullCache(), TenantScoped(tenantId), NullLog());
        var result = await repo.GetPermissionsForUserAsync("identity-tenant-a");

        result.Should().ContainSingle().Which.Should().Be("Permission.Invoice.Read",
            "a global role's permissions must resolve for a real tenant-scoped user — this is " +
            "exactly the seeded-roles + multi-tenant combination Crestacle.Bedrock.Sentinel exists " +
            "to support");
    }

    [Fact]
    public async Task GetPermissionsForUserAsync_ReturnsEmpty_ForUnknownUser()
    {
        await using var ctx = BuildContext();
        var repo = new UserPermissionRepository(ctx, NullCache(), NullTenant(), NullLog());

        var result = await repo.GetPermissionsForUserAsync("nobody");

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task GetPermissionsForUserAsync_ReturnsCachedResult_WithoutHittingDb()
    {
        var cachedPerms = new HashSet<string> { "Permission.Invoice.Read" };

        var cache = Substitute.For<IPermissionCache>();
        cache.GetAsync("identity-cached", Arg.Any<CancellationToken>())
             .Returns(cachedPerms);

        // Empty DB — if the cache is bypassed the result would be empty.
        await using var ctx = BuildContext();
        var repo = new UserPermissionRepository(ctx, cache, NullTenant(), NullLog());

        var result = await repo.GetPermissionsForUserAsync("identity-cached");

        result.Should().BeEquivalentTo(cachedPerms);
        await cache.Received(1).GetAsync("identity-cached", Arg.Any<CancellationToken>());
        await cache.DidNotReceive().SetAsync(Arg.Any<string>(), Arg.Any<HashSet<string>>(), Arg.Any<CancellationToken>());
    }
}
