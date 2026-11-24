using Crestacle.Sentinel.Core.Authorization;
using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Exceptions;
using Crestacle.Sentinel.Core.Interfaces;
using Crestacle.Sentinel.EntityFramework;
using Crestacle.Sentinel.EntityFramework.Extensions;
using Crestacle.Sentinel.EntityFramework.Repositories;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Crestacle.Sentinel.Tests.EntityFramework;

/// <summary>
/// SQLite has no native rowversion-generation mechanism (same gap documented for PostgreSQL in
/// ModelBuilderExtensions.UseSentinelPostgreSqlConcurrency) -- IsRowVersion() produces a NOT NULL
/// column SQLite never populates, so inserts fail. This test context isn't exercising
/// concurrency-token behaviour, so the RowVersion columns are simply made non-DB-generated.
/// </summary>
internal sealed class TestSqliteAuthDbContext(DbContextOptions<TestSqliteAuthDbContext> options)
    : DbContext(options), IAuthDbContext
{
    public DbSet<User>               Users               => Set<User>();
    public DbSet<Role>               Roles               => Set<Role>();
    public DbSet<Permission>         Permissions         => Set<Permission>();
    public DbSet<UserRole>           UserRoles           => Set<UserRole>();
    public DbSet<RolePermission>     RolePermissions     => Set<RolePermission>();
    public DbSet<AuditEntry>         AuditLog            => Set<AuditEntry>();
    public DbSet<PermissionConflict> PermissionConflicts => Set<PermissionConflict>();
    public DbSet<PendingAssignment>  PendingAssignments  => Set<PendingAssignment>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.ApplySentinelConfiguration();
        builder.Entity<Role>().Property(r => r.RowVersion).ValueGeneratedNever();
        builder.Entity<Permission>().Property(p => p.RowVersion).ValueGeneratedNever();
        builder.Entity<PendingAssignment>().Property(pa => pa.RowVersion).ValueGeneratedNever();
    }
}

/// <summary>
/// Exercises RoleRepository.AddPermissionAsync's Separation-of-Duties guard under real
/// concurrency against a genuinely relational provider (SQLite), unlike the InMemory provider
/// used elsewhere in this test project, which does not support transactions at all.
/// </summary>
public sealed class RolePermissionConflictConcurrencyTests : IAsyncLifetime
{
    private const string ConnectionString = "DataSource=file:sentinel_sod_concurrency?mode=memory&cache=shared";

    // Keeps the shared in-memory SQLite database alive for the test's lifetime -- without an
    // open connection, the in-memory database is destroyed as soon as the last connection to it
    // closes, and every NewContext() call opens/closes its own short-lived connection.
    private SqliteConnection _keepAlive = null!;

    public async Task InitializeAsync()
    {
        _keepAlive = new SqliteConnection(ConnectionString);
        await _keepAlive.OpenAsync();

        using var context = NewContext();
        await context.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync() => await _keepAlive.DisposeAsync();

    private static TestSqliteAuthDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<TestSqliteAuthDbContext>()
            .UseSqlite(ConnectionString)
            .Options;
        return new TestSqliteAuthDbContext(options);
    }

    private static RoleRepository BuildRepository(TestSqliteAuthDbContext context)
    {
        var actor = Substitute.For<ICurrentActor>();
        actor.IdentityId.Returns("test-actor");

        var cache = Substitute.For<IPermissionCache>();

        var tenant = Substitute.For<ITenantContext>();
        tenant.TenantId.Returns((string?)null);

        var conflictRepo = new PermissionConflictRepository(context, actor, tenant);

        var logger = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance
            .CreateLogger<RoleRepository>();

        return new RoleRepository(context, actor, cache, tenant, conflictRepo, logger);
    }

    [Fact]
    public async Task AddPermissionAsync_ConcurrentConflictingGrants_OnlyOneSucceeds()
    {
        var roleId = Guid.NewGuid();
        const string permA = "Permission.Invoice.Create";
        const string permB = "Permission.Invoice.Approve";

        using (var seed = NewContext())
        {
            var role = Role.Create("invoicer", "Invoicer", RoleType.Default);
            roleId = role.Id;

            seed.Roles.Add(role);
            seed.Permissions.Add(Permission.Create(new AppPermission("Invoice", "Create", "Finance", "")));
            seed.Permissions.Add(Permission.Create(new AppPermission("Invoice", "Approve", "Finance", "")));
            seed.PermissionConflicts.Add(PermissionConflict.Create(permA, permB, "system"));
            await seed.SaveChangesAsync();
        }

        using var ctx1 = NewContext();
        using var ctx2 = NewContext();
        var repo1 = BuildRepository(ctx1);
        var repo2 = BuildRepository(ctx2);

        var task1 = TryAddAsync(repo1, roleId, permA);
        var task2 = TryAddAsync(repo2, roleId, permB);

        var results = await Task.WhenAll(task1, task2);

        results.Count(r => r == Outcome.Succeeded).Should().Be(1,
            "exactly one of the two mutually-conflicting grants must win");
        results.Count(r => r == Outcome.RejectedAsConflict).Should().Be(1,
            "the losing grant must be rejected as a Separation-of-Duties conflict, not silently applied");

        using var verify = NewContext();
        var activeCount = await verify.RolePermissions
            .CountAsync(rp => rp.RoleId == roleId && rp.RemovedOn == null);
        activeCount.Should().Be(1,
            "both conflicting permissions must never end up active on the role at the same time");
    }

    private enum Outcome { Succeeded, RejectedAsConflict }

    private static async Task<Outcome> TryAddAsync(RoleRepository repo, Guid roleId, string permissionId)
    {
        try
        {
            await repo.AddPermissionAsync(roleId, permissionId);
            return Outcome.Succeeded;
        }
        catch (SentinelPermissionConflictException)
        {
            return Outcome.RejectedAsConflict;
        }
    }
}
