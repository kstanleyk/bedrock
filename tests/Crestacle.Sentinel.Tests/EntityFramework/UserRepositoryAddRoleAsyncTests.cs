using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Exceptions;
using Crestacle.Sentinel.Core.Interfaces;
using Crestacle.Sentinel.EntityFramework.Repositories;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Crestacle.Sentinel.Tests.EntityFramework;

/// <summary>
/// Regression coverage for UserRepository.AddRoleAsync's tenant-ownership check: a role must
/// belong to the acting tenant (or be global, TenantId == null) before it can be attached to
/// any user. Without this, a tenant-A actor holding only User.Update could attach an arbitrary
/// tenant-B-only role (by guessing/enumerating its GUID) to a tenant-A user.
/// </summary>
public sealed class UserRepositoryAddRoleAsyncTests
{
    private static TestAuthDbContext BuildContext()
    {
        var opts = new DbContextOptionsBuilder<TestAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new TestAuthDbContext(opts);
    }

    private static UserRepository BuildRepo(TestAuthDbContext ctx, string? tenantId)
    {
        var actor = Substitute.For<ICurrentActor>();
        var cache = Substitute.For<IPermissionCache>();
        var tenantContext = Substitute.For<ITenantContext>();
        tenantContext.TenantId.Returns(tenantId);
        var eventPublisher = Substitute.For<ISentinelEventPublisher>();
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance
            .CreateLogger<UserRepository>();

        return new UserRepository(ctx, actor, cache, tenantContext, eventPublisher, logger);
    }

    [Fact]
    public async Task AddRoleAsync_RoleBelongsToADifferentTenant_ThrowsNotFound()
    {
        await using var ctx = BuildContext();

        var user = User.Create("identity-cross-tenant", "user@tenant-a.test", tenantId: "tenant-a");
        var foreignRole = Role.Create("TenantBOnly", "Tenant B Only", RoleType.Default, tenantId: "tenant-b");
        ctx.Users.Add(user);
        ctx.Roles.Add(foreignRole);
        await ctx.SaveChangesAsync();

        var repo = BuildRepo(ctx, "tenant-a");

        var act = async () => await repo.AddRoleAsync(user.Id, foreignRole.Id);

        await act.Should().ThrowAsync<SentinelNotFoundException>(
            "a tenant-a actor must not be able to attach a tenant-b-only role to any user");

        (await ctx.UserRoles.AnyAsync(ur => ur.UserId == user.Id)).Should().BeFalse(
            "no UserRole row must be created when the role doesn't belong to the acting tenant");
    }

    [Fact]
    public async Task AddRoleAsync_RoleBelongsToTheSameTenant_Succeeds()
    {
        await using var ctx = BuildContext();

        var user = User.Create("identity-same-tenant", "user@tenant-a.test", tenantId: "tenant-a");
        var ownRole = Role.Create("TenantAOwn", "Tenant A Own", RoleType.Default, tenantId: "tenant-a");
        ctx.Users.Add(user);
        ctx.Roles.Add(ownRole);
        await ctx.SaveChangesAsync();

        var repo = BuildRepo(ctx, "tenant-a");

        await repo.AddRoleAsync(user.Id, ownRole.Id);

        (await ctx.UserRoles.AnyAsync(ur => ur.UserId == user.Id && ur.RoleId == ownRole.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task AddRoleAsync_GlobalRole_SucceedsForAnyTenant()
    {
        await using var ctx = BuildContext();

        var user = User.Create("identity-global-role", "user@tenant-a.test", tenantId: "tenant-a");
        var globalRole = Role.Create("Global", "Global Role", RoleType.Default, tenantId: null);
        ctx.Users.Add(user);
        ctx.Roles.Add(globalRole);
        await ctx.SaveChangesAsync();

        var repo = BuildRepo(ctx, "tenant-a");

        await repo.AddRoleAsync(user.Id, globalRole.Id);

        (await ctx.UserRoles.AnyAsync(ur => ur.UserId == user.Id && ur.RoleId == globalRole.Id)).Should().BeTrue(
            "a global/shared role must be assignable by any tenant's actor");
    }

    [Fact]
    public async Task AddRoleAsync_RoleDoesNotExistAtAll_ThrowsNotFound()
    {
        await using var ctx = BuildContext();

        var user = User.Create("identity-no-role", "user@tenant-a.test", tenantId: "tenant-a");
        ctx.Users.Add(user);
        await ctx.SaveChangesAsync();

        var repo = BuildRepo(ctx, "tenant-a");

        var act = async () => await repo.AddRoleAsync(user.Id, Guid.NewGuid());

        await act.Should().ThrowAsync<SentinelNotFoundException>();
    }
}
