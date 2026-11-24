using Crestacle.Sentinel.Core.Interfaces;
using Crestacle.Sentinel.EntityFramework.Caching;
using Crestacle.Sentinel.EntityFramework.Events;
using Crestacle.Sentinel.EntityFramework.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Crestacle.Sentinel.EntityFramework;

public static class DependencyInjection
{
    /// <summary>
    /// Registers Sentinel repository implementations, the default in-memory permission cache,
    /// and a NullTenantContext (single-tenant, no filtering).
    /// TContext must implement IAuthDbContext.
    ///
    /// To enable multi-tenancy, register your own ITenantContext implementation after this call:
    ///   services.AddSentinelRepositories&lt;MyContext&gt;();
    ///   services.AddScoped&lt;ITenantContext, MyJwtTenantContext&gt;();
    ///
    /// To use a distributed cache (e.g. Redis), register IPermissionCache after this call:
    ///   services.AddSingleton&lt;IPermissionCache, RedisPermissionCache&gt;();
    ///
    /// To configure the permission cache TTL (defaults to 5 minutes):
    ///   services.AddSentinelRepositories&lt;MyContext&gt;(o => o.PermissionCacheTtl = TimeSpan.FromMinutes(1));
    ///
    /// To disable caching entirely (immediate revocation, higher DB load):
    ///   services.AddSentinelRepositories&lt;MyContext&gt;(o => o.PermissionCacheTtl = TimeSpan.Zero);
    /// </summary>
    public static IServiceCollection AddSentinelRepositories<TContext>(
        this IServiceCollection  services,
        Action<SentinelOptions>? configure = null)
        where TContext : DbContext, IAuthDbContext
    {
        var options = new SentinelOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);

        // Default single-tenant context — override with your own ITenantContext for multi-tenancy.
        services.AddSingleton<ITenantContext, NullTenantContext>();

        // Default in-memory permission cache — override with IPermissionCache for distributed cache.
        services.AddMemoryCache();
        services.AddSingleton<IPermissionCache, MemoryPermissionCache>();

        // Default no-op event publisher — override with ISentinelEventPublisher to receive domain events.
        services.AddScoped<ISentinelEventPublisher, NullSentinelEventPublisher>();

        services.AddScoped<IUserPermissionRepository>(sp =>
            new UserPermissionRepository(
                sp.GetRequiredService<TContext>(),
                sp.GetRequiredService<IPermissionCache>(),
                sp.GetRequiredService<ITenantContext>(),
                sp.GetRequiredService<ILogger<UserPermissionRepository>>()));

        services.AddScoped<IRoleRepository>(sp =>
            new RoleRepository(
                sp.GetRequiredService<TContext>(),
                sp.GetRequiredService<ICurrentActor>(),
                sp.GetRequiredService<IPermissionCache>(),
                sp.GetRequiredService<ITenantContext>(),
                sp.GetRequiredService<IPermissionConflictRepository>(),
                sp.GetRequiredService<ILogger<RoleRepository>>()));

        services.AddScoped<IUserRepository>(sp =>
            new UserRepository(
                sp.GetRequiredService<TContext>(),
                sp.GetRequiredService<ICurrentActor>(),
                sp.GetRequiredService<IPermissionCache>(),
                sp.GetRequiredService<ITenantContext>(),
                sp.GetRequiredService<ISentinelEventPublisher>(),
                sp.GetRequiredService<ILogger<UserRepository>>()));

        services.AddScoped<IPermissionConflictRepository>(sp =>
            new PermissionConflictRepository(
                sp.GetRequiredService<TContext>(),
                sp.GetRequiredService<ICurrentActor>(),
                sp.GetRequiredService<ITenantContext>()));

        services.AddScoped<IPendingAssignmentRepository>(sp =>
            new PendingAssignmentRepository(
                sp.GetRequiredService<TContext>(),
                sp.GetRequiredService<ICurrentActor>(),
                sp.GetRequiredService<IPermissionCache>(),
                sp.GetRequiredService<ITenantContext>(),
                sp.GetRequiredService<ISentinelEventPublisher>(),
                sp.GetRequiredService<ILogger<PendingAssignmentRepository>>()));

        services.AddScoped<IAuditRepository>(sp =>
            new AuditRepository(sp.GetRequiredService<TContext>()));

        return services;
    }
}
