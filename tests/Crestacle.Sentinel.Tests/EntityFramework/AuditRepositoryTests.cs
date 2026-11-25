using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Interfaces;
using Crestacle.Sentinel.EntityFramework.Repositories;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using NSubstitute;

namespace Crestacle.Sentinel.Tests.EntityFramework;

/// <summary>
/// Verifies AuditRepository.GetAsync is tenant-scoped, closing the cross-tenant audit-log
/// disclosure: previously AuditEntry carried no TenantId at all, so any caller with Audit.Read
/// could see every tenant's audit history.
/// </summary>
public sealed class AuditRepositoryTests
{
    private static TestAuthDbContext BuildContext()
    {
        var opts = new DbContextOptionsBuilder<TestAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new TestAuthDbContext(opts);
    }

    private static ITenantContext TenantScoped(string? tenantId)
    {
        var ctx = Substitute.For<ITenantContext>();
        ctx.TenantId.Returns(tenantId);
        return ctx;
    }

    private static async Task SeedAsync(TestAuthDbContext ctx)
    {
        ctx.AuditLog.Add(AuditEntry.Create(
            AuditAction.RoleAssigned, "tenant-a-entity", "actor-a", "127.0.0.1", "ua", "tenant-a"));
        ctx.AuditLog.Add(AuditEntry.Create(
            AuditAction.RoleRemoved, "tenant-a-entity-2", "actor-a", "127.0.0.1", "ua", "tenant-a"));
        ctx.AuditLog.Add(AuditEntry.Create(
            AuditAction.PermissionAssigned, "tenant-b-entity", "actor-b", "127.0.0.1", "ua", "tenant-b"));
        await ctx.SaveChangesAsync();
    }

    [Fact]
    public async Task GetAsync_TenantScopedCaller_OnlySeesItsOwnTenantsRows()
    {
        await using var ctx = BuildContext();
        await SeedAsync(ctx);

        var repoA = new AuditRepository(ctx, TenantScoped("tenant-a"));
        var resultA = await repoA.GetAsync();

        resultA.Items.Should().HaveCount(2);
        resultA.Items.Should().OnlyContain(e => e.EntityId.StartsWith("tenant-a"));
    }

    [Fact]
    public async Task GetAsync_OtherTenantScopedCaller_DoesNotSeeFirstTenantsRows()
    {
        await using var ctx = BuildContext();
        await SeedAsync(ctx);

        var repoB = new AuditRepository(ctx, TenantScoped("tenant-b"));
        var resultB = await repoB.GetAsync();

        resultB.Items.Should().ContainSingle();
        resultB.Items.Single().EntityId.Should().Be("tenant-b-entity");
    }

    [Fact]
    public async Task GetAsync_NullTenantContext_IsUnfiltered_SingleTenantModeByDesign()
    {
        await using var ctx = BuildContext();
        await SeedAsync(ctx);

        var repo = new AuditRepository(ctx, TenantScoped(null));
        var result = await repo.GetAsync();

        result.Items.Should().HaveCount(3,
            "a null TenantId means single-tenant mode — no filtering — by design across all " +
            "Sentinel repositories, same convention as UserPermissionRepository");
    }
}
