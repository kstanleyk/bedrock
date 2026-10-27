using System.Security.Claims;
using Crestacle.Bedrock.AspNetCore.Authorization;
using Crestacle.Bedrock.AspNetCore.BackgroundServices;
using Crestacle.Bedrock.AspNetCore.Conventions;
using Crestacle.Bedrock.AspNetCore.Helpers;
using Crestacle.Bedrock.AspNetCore.Services;
using Crestacle.Bedrock.Core.Defaults;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Extensions;

/// <summary>Extension methods for registering Bedrock services in an ASP.NET Core DI container.</summary>
public static class BedrockAspNetCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers all Bedrock AspNetCore services: JWT authentication, authorization policies,
    /// password hashing, MFA, step-up, session management, anomaly detection, and null senders.
    /// Call <see cref="AddBedrockControllers"/> afterward to also register the built-in controllers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why is there no <c>AddBedrock&lt;TContext&gt;()</c> convenience method here?</b>
    /// <c>Crestacle.Bedrock.AspNetCore</c> and <c>Crestacle.Bedrock.EntityFramework</c>
    /// intentionally do not reference each other — the consuming application is the composition
    /// root that wires both packages together. Adding such a method to either package would
    /// violate that boundary.
    /// </para>
    /// <para>
    /// Copy the one-liner wrapper below into your application project once and it becomes
    /// indistinguishable from a compiled extension method:
    /// <code>
    /// public static IBedrockBuilder AddBedrock&lt;TContext&gt;(
    ///     this IServiceCollection services,
    ///     Action&lt;BedrockOptions&gt;? configure = null)
    ///     where TContext : BedrockContext
    /// {
    ///     services.AddBedrockEntityFramework&lt;TContext&gt;();
    ///     return services.AddBedrockAspNetCore(configure);
    /// }
    /// </code>
    /// See README.md § "Convenience Wrapper" for the full snippet and usage example.
    /// </para>
    /// </remarks>
    /// <param name="services">The application's <see cref="IServiceCollection"/>.</param>
    /// <param name="configure">Optional delegate to configure <see cref="BedrockOptions"/>.</param>
    /// <returns>An <see cref="IBedrockBuilder"/> for fluent <c>With*</c> overrides.</returns>
    public static IBedrockBuilder AddBedrockAspNetCore(
        this IServiceCollection services,
        Action<BedrockOptions>? configure = null)
    {
        services.AddOptions();
        services.AddLogging();

        if (configure is not null)
            services.Configure<BedrockOptions>(configure);

        // --- DataProtection (required by TotpService for TOTP secret encryption) ---
        services.AddDataProtection();

        // --- Extensibility defaults (replaced by consumer via TryAdd before calling this) ---
        services.TryAddScoped<IEmailSender, NullEmailSender>();
        services.TryAddSingleton<ISmsSender, NullSmsSender>();
        services.TryAddSingleton<IBedrockEventPublisher, NullBedrockEventPublisher>();
        services.TryAddSingleton<IBedrockClaimsEnricher, NullBedrockClaimsEnricher>();
        services.TryAddSingleton<IBedrockCache, NullBedrockCache>();
        // SingleRealmProvider always resolves the same no-realm-concept BedrockRealm regardless
        // of host -- every consumer that never calls WithRealmProvider<T>() (multi-realm hosting)
        // sees zero behavior change; the realm-scoped values it exposes are read straight from
        // this SAME IOptions<BedrockOptions> registration.
        services.AddHttpContextAccessor();
        services.TryAddSingleton<IBedrockRealmProvider, SingleRealmProvider>();

        // --- Password / credential services ---
        services.AddScoped<IPasswordHasher, Argon2idPasswordHasher>();
        services.AddSingleton<CommonPasswordValidator>();
        services.AddScoped<IPasswordValidator, DefaultPasswordValidator>();
        services.AddScoped<IMfaPolicyService, MfaPolicyService>();
        services.AddScoped<IAnomalyDetector, AnomalyDetector>();
        services.AddScoped<ICredentialService, CredentialService>();
        services.AddScoped<IConsentService, ConsentService>();

        // --- MFA services ---
        services.AddScoped<IMfaService, TotpService>();
        services.AddScoped<IOtpService, OtpService>();
        services.AddScoped<OtpSendLimiter>();

        // --- Session services ---
        services.AddScoped<ISessionService, SessionService>();

        // --- Step-up services ---
        services.AddScoped<IStepUpService, StepUpService>();

        // --- Token services ---
        services.AddScoped<ITokenService, JwtService>();
        services.TryAddScoped<IBedrockTokenIssuer, JwtBedrockTokenIssuer>();
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();

        // --- Admin management ---
        services.AddScoped<IBedrockAdminService, BedrockAdminService>();
        services.AddScoped<IInvitationService, InvitationService>();
        services.AddScoped<IApiKeyService, ApiKeyService>();

        // --- External identity federation ---
        services.AddScoped<IExternalLoginService, ExternalLoginService>();

        // --- Passkey (WebAuthn/FIDO2) ---
        services.AddSingleton<IFido2>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<BedrockOptions>>().Value.Passkey;
            return new Fido2(new Fido2Configuration
            {
                ServerDomain = opts.ServerDomain,
                ServerName = opts.ServerName,
                Origins = opts.Origins,
                TimestampDriftTolerance = opts.TimestampDriftToleranceMs
            });
        });
        services.AddScoped<IPasskeyService, PasskeyService>();

        // --- JWT bearer authentication ---
        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        // Configure JwtBearerOptions lazily from BedrockOptions so that IOptions<BedrockOptions>
        // is fully resolved (including any Configure calls) before we read jwt settings.
        services
            .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<BedrockOptions>>((jwtOpts, bedrockOpts) =>
            {
                var jwt = bedrockOpts.Value.Jwt;
                if (jwt.ExternalTokenIssuer || (string.IsNullOrEmpty(jwt.SigningKey) && jwt.SigningCertificate is null))
                    return; // External IDP or no key configured; skip Bedrock JWT Bearer setup

                jwtOpts.TokenValidationParameters = BedrockJwtHelper.BuildValidationParameters(jwt);

                // Reject access tokens whose JTI has been blacklisted in the revocation cache
                // (e.g. after password change, password reset, or explicit session revocation).
                jwtOpts.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async ctx =>
                    {
                        var jti = ctx.SecurityToken?.Id;
                        if (string.IsNullOrEmpty(jti)) return;

                        var cache = ctx.HttpContext.RequestServices
                            .GetRequiredService<IBedrockCache>();
                        if (await cache.ExistsAsync(
                                "Bedrock:revoked:" + jti,
                                ctx.HttpContext.RequestAborted))
                        {
                            ctx.Fail("Access token has been revoked.");
                        }
                    }
                };
            });

        // --- Authorization policies ---
        services.AddAuthorization(authOpts =>
        {
            authOpts.AddPolicy(BedrockPolicyNames.Default, p => p
                .RequireAuthenticatedUser()
                .RequireAssertion(ctx =>
                    ctx.User.FindFirstValue("token_type") != "enrollment"));

            authOpts.AddPolicy(BedrockPolicyNames.MfaEnrollment, p => p
                .RequireAuthenticatedUser()
                .RequireAssertion(ctx =>
                    ctx.User.FindFirstValue("token_type") == "enrollment"));

            authOpts.AddPolicy(BedrockPolicyNames.Admin, p => p
                .RequireAuthenticatedUser()
                .RequireClaim("bedrock_admin", "true"));
        });

        return new BedrockBuilder(services);
    }

    /// <summary>
    /// Registers Bedrock's built-in MVC controllers under <paramref name="basePath"/>.
    /// Also registers the <see cref="BedrockExpiryService"/> background service.
    /// </summary>
    /// <param name="builder">The Bedrock builder returned by <see cref="AddBedrockAspNetCore"/>.</param>
    /// <param name="basePath">
    /// The route prefix for all built-in Bedrock endpoints; defaults to <c>api/bedrock</c>.
    /// API versioning is the host's concern: pass any prefix the host wants
    /// (e.g. <c>"api/v1/auth"</c>) and Bedrock will mount its routes underneath it.
    /// </param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder AddBedrockControllers(
        this IBedrockBuilder builder,
        string basePath = "api/bedrock")
    {
        builder.Services
            .AddControllers()
            .AddApplicationPart(typeof(BedrockAspNetCoreServiceCollectionExtensions).Assembly)
            .AddMvcOptions(opts => opts.Conventions.Add(new BedrockRouteConvention(basePath)));

        builder.Services.AddHostedService<BedrockExpiryService>();

        return builder;
    }

    /// <summary>
    /// Wraps the registered <see cref="IBedrockClaimsEnricher"/> in a caching decorator that
    /// stores <c>EnrichAsync</c> and <c>GetRolesAsync</c> results in <see cref="IBedrockCache"/>
    /// for <paramref name="duration"/>, eliminating one application-DB round-trip per token refresh.
    /// </summary>
    /// <remarks>
    /// Must be called <em>after</em> <see cref="AddBedrockAspNetCore"/> and after any custom
    /// <c>IBedrockClaimsEnricher</c> registration. Cache keys are
    /// <c>Bedrock:claims:{userId}</c> and <c>Bedrock:roles:{userId}</c>. Invalidate early by
    /// calling <c>IBedrockCache.RemoveAsync</c> on those keys after a role change.
    /// </remarks>
    /// <param name="builder">The Bedrock builder.</param>
    /// <param name="duration">How long to cache enricher results per user.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithClaimsEnricherCache(
        this IBedrockBuilder builder,
        TimeSpan duration)
    {
        builder.Services.Configure<BedrockOptions>(opts => opts.ClaimsCache.Duration = duration);

        // Find the most-recently-registered IBedrockClaimsEnricher descriptor
        var descriptor = builder.Services
            .LastOrDefault(d => d.ServiceType == typeof(IBedrockClaimsEnricher));

        if (descriptor is null)
            return builder;

        builder.Services.Remove(descriptor);

        // Build a factory that instantiates the original enricher from the captured descriptor
        Func<IServiceProvider, IBedrockClaimsEnricher> innerFactory = descriptor switch
        {
            { ImplementationType: not null } =>
                sp => (IBedrockClaimsEnricher)ActivatorUtilities.CreateInstance(sp, descriptor.ImplementationType),
            { ImplementationFactory: not null } =>
                sp => (IBedrockClaimsEnricher)descriptor.ImplementationFactory(sp),
            { ImplementationInstance: not null } =>
                _ => (IBedrockClaimsEnricher)descriptor.ImplementationInstance,
            _ => _ => new NullBedrockClaimsEnricher()
        };

        builder.Services.Add(new ServiceDescriptor(
            typeof(IBedrockClaimsEnricher),
            sp => new CachingBedrockClaimsEnricher(
                innerFactory(sp),
                sp.GetRequiredService<IBedrockCache>(),
                sp.GetRequiredService<IOptions<BedrockOptions>>()),
            descriptor.Lifetime));

        return builder;
    }
}
