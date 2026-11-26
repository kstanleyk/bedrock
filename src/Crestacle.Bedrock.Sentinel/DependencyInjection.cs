using Crestacle.Bedrock.AspNetCore;
using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.EntityFramework;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Crestacle.Bedrock.Core.Options;
using Crestacle.Sentinel.AspNetCore;
using Crestacle.Sentinel.EntityFramework;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using BedrockTenant  = Crestacle.Bedrock.Core.Interfaces.ITenantContext;
using SentinelTenant = Crestacle.Sentinel.Core.Interfaces.ITenantContext;

namespace Crestacle.Bedrock.Sentinel;

/// <summary>
/// Extension methods that wire Bedrock (authentication) and Sentinel (RBAC authorisation)
/// into a single composable registration.
/// </summary>
public static class DependencyInjection
{
    /// <summary>
    /// Registers Sentinel repositories, authorisation services, and a tenant context adapter
    /// that forwards Bedrock's <see cref="BedrockTenant"/> to Sentinel.
    /// </summary>
    /// <typeparam name="TSentinelContext">
    /// The application's EF Core DbContext that implements
    /// <see cref="Crestacle.Sentinel.EntityFramework.IAuthDbContext"/>.
    /// </typeparam>
    /// <param name="builder">The <see cref="IBedrockBuilder"/> returned by <c>AddBedrockAspNetCore()</c>.</param>
    /// <param name="configure">Optional delegate to configure <see cref="SentinelOptions"/>.</param>
    /// <returns>The same builder for further chaining.</returns>
    public static IBedrockBuilder AddSentinel<TSentinelContext>(
        this IBedrockBuilder builder,
        Action<SentinelOptions>? configure = null)
        where TSentinelContext : DbContext, IAuthDbContext
    {
        builder.Services.AddSentinelRepositories<TSentinelContext>(configure);
        builder.Services.AddSentinelAuthorization();

        // Replace Sentinel's NullTenantContext with an adapter that reads from Bedrock's
        // ITenantContext, ensuring both libraries see the same tenant on every request.
        builder.Services.RemoveAll<SentinelTenant>();
        builder.Services.AddScoped<SentinelTenant>(sp =>
            new BedrockTenantContextAdapter(sp.GetRequiredService<BedrockTenant>()));

        return builder;
    }

    /// <summary>
    /// Registers a <see cref="SentinelClaimsEnricher"/> that embeds Sentinel RBAC data and
    /// Bedrock credential metadata into every issued JWT.
    /// </summary>
    /// <remarks>
    /// The enricher adds: one <c>"Permission.{Feature}.{Action}" = "true"</c> claim per granted
    /// permission, a <c>"name"</c> claim (user's full name), and an <c>"mfa_enabled"</c> claim.
    /// Role names are embedded via <c>GetRolesAsync</c> and appear as standard JWT role claims.
    /// <c>[MustHavePermission]</c> resolves permissions from the database with caching and does
    /// not require permission claims in the token — include this enricher when clients need a
    /// self-contained token they can evaluate without a back-channel call.
    /// </remarks>
    /// <param name="builder">The <see cref="IBedrockBuilder"/> after <c>AddSentinel()</c>.</param>
    /// <returns>The same builder for further chaining.</returns>
    public static IBedrockBuilder WithPermissionClaims(this IBedrockBuilder builder)
    {
        // Replace the default NullBedrockClaimsEnricher registered by AddBedrockAspNetCore().
        builder.Services.RemoveAll<IBedrockClaimsEnricher>();
        builder.Services.AddScoped<IBedrockClaimsEnricher, SentinelClaimsEnricher>();

        return builder;
    }

    /// <summary>
    /// Registers a <see cref="SentinelProfileClaimsEnricher"/> that embeds the user's name,
    /// MFA status, and role names into every issued JWT -- without the per-permission claims
    /// <see cref="WithPermissionClaims"/> adds.
    /// </summary>
    /// <remarks>
    /// Use this when your app needs the caller's name/MFA/role on every token but does not want
    /// one claim per granted permission inflating token size (large permission sets can push a
    /// JWT past a reverse proxy's default header-buffer size). Permissions stay available via
    /// <c>GET api/auth/permissions/me</c> regardless -- <c>[MustHavePermission]</c> never depends
    /// on token claims. Mutually exclusive with <see cref="WithPermissionClaims"/>: whichever is
    /// called last wins, since both replace the single registered <see cref="IBedrockClaimsEnricher"/>.
    /// </remarks>
    /// <param name="builder">The <see cref="IBedrockBuilder"/> after <c>AddSentinel()</c>.</param>
    /// <returns>The same builder for further chaining.</returns>
    public static IBedrockBuilder WithProfileClaims(this IBedrockBuilder builder)
    {
        // Replace the default NullBedrockClaimsEnricher registered by AddBedrockAspNetCore().
        builder.Services.RemoveAll<IBedrockClaimsEnricher>();
        builder.Services.AddScoped<IBedrockClaimsEnricher, SentinelProfileClaimsEnricher>();

        return builder;
    }

    /// <summary>
    /// Convenience method that registers the full Bedrock + Sentinel stack in one call.
    /// Equivalent to calling:
    /// <code>
    /// services.AddBedrockEntityFramework&lt;TBedrockContext&gt;()
    ///         .AddBedrockAspNetCore(configure)
    ///         .AddSentinel&lt;TSentinelContext&gt;(sentinelConfigure);
    /// </code>
    /// </summary>
    /// <typeparam name="TBedrockContext">
    /// The application's <see cref="BedrockContext"/>-derived DbContext.
    /// </typeparam>
    /// <typeparam name="TSentinelContext">
    /// The application's EF Core DbContext that implements
    /// <see cref="Crestacle.Sentinel.EntityFramework.IAuthDbContext"/>.
    /// </typeparam>
    /// <param name="services">The application's <see cref="IServiceCollection"/>.</param>
    /// <param name="configure">Optional delegate to configure <see cref="BedrockOptions"/>.</param>
    /// <param name="sentinelConfigure">Optional delegate to configure <see cref="SentinelOptions"/>.</param>
    /// <returns>An <see cref="IBedrockBuilder"/> for further <c>With*</c> overrides.</returns>
    public static IBedrockBuilder AddBedrockWithSentinel<TBedrockContext, TSentinelContext>(
        this IServiceCollection services,
        Action<BedrockOptions>? configure = null,
        Action<SentinelOptions>? sentinelConfigure = null)
        where TBedrockContext    : BedrockContext
        where TSentinelContext   : DbContext, IAuthDbContext
    {
        services.AddBedrockEntityFramework<TBedrockContext>();

        return services
            .AddBedrockAspNetCore(configure)
            .AddSentinel<TSentinelContext>(sentinelConfigure);
    }
}
