using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Crestacle.Bedrock.AspNetCore.Extensions;

/// <summary>Fluent <c>With*</c> overrides and convenience helpers on <see cref="IBedrockBuilder"/>.</summary>
public static class BedrockBuilderExtensions
{
    /// <summary>Builds the <see cref="ServiceProvider"/> from the builder's service collection.</summary>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>A new <see cref="ServiceProvider"/>.</returns>
    public static ServiceProvider BuildServiceProvider(this IBedrockBuilder builder)
        => builder.Services.BuildServiceProvider();

    /// <summary>Builds the <see cref="ServiceProvider"/> from the builder's service collection.</summary>
    /// <param name="builder">The Bedrock builder.</param>
    /// <param name="options">Options to control validation and scope behaviour.</param>
    /// <returns>A new <see cref="ServiceProvider"/>.</returns>
    public static ServiceProvider BuildServiceProvider(
        this IBedrockBuilder builder,
        ServiceProviderOptions options)
        => builder.Services.BuildServiceProvider(options);

    /// <summary>Replaces the default no-op <see cref="IEmailSender"/> with <typeparamref name="T"/>.</summary>
    /// <typeparam name="T">The concrete email sender implementation to register as scoped.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithEmailSender<T>(this IBedrockBuilder builder)
        where T : class, IEmailSender
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(IEmailSender));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddScoped<IEmailSender, T>();
        return builder;
    }

    /// <summary>Replaces the default no-op <see cref="ISmsSender"/> with <typeparamref name="T"/>.</summary>
    /// <typeparam name="T">The concrete SMS sender implementation to register as singleton.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithSmsSender<T>(this IBedrockBuilder builder)
        where T : class, ISmsSender
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(ISmsSender));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddSingleton<ISmsSender, T>();
        return builder;
    }

    /// <summary>Replaces the default no-op <see cref="IBedrockEventPublisher"/> with <typeparamref name="T"/>.</summary>
    /// <typeparam name="T">The concrete event publisher to register as singleton.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithEventPublisher<T>(this IBedrockBuilder builder)
        where T : class, IBedrockEventPublisher
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(IBedrockEventPublisher));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddSingleton<IBedrockEventPublisher, T>();
        return builder;
    }

    /// <summary>Replaces the default no-op <see cref="IBedrockClaimsEnricher"/> with <typeparamref name="T"/>.</summary>
    /// <typeparam name="T">The concrete claims enricher to register as singleton.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithClaimsEnricher<T>(this IBedrockBuilder builder)
        where T : class, IBedrockClaimsEnricher
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(IBedrockClaimsEnricher));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddSingleton<IBedrockClaimsEnricher, T>();
        return builder;
    }

    /// <summary>Replaces the default in-memory <see cref="IBedrockCache"/> with a custom implementation.</summary>
    /// <typeparam name="T">The concrete cache to register as singleton; use a Redis-backed type for distributed deployments.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithCache<T>(this IBedrockBuilder builder)
        where T : class, IBedrockCache
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(IBedrockCache));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddSingleton<IBedrockCache, T>();
        return builder;
    }

    /// <summary>Registers a scoped <see cref="ITenantContext"/> implementation for multi-tenant query filtering.</summary>
    /// <typeparam name="T">The concrete tenant context to register as scoped.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithTenantContext<T>(this IBedrockBuilder builder)
        where T : class, ITenantContext
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(ITenantContext));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddScoped<ITenantContext, T>();
        return builder;
    }

    /// <summary>Replaces the default Argon2id <see cref="IPasswordHasher"/> with a custom implementation.</summary>
    /// <typeparam name="T">The concrete password hasher to register as scoped.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithPasswordHasher<T>(this IBedrockBuilder builder)
        where T : class, IPasswordHasher
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(IPasswordHasher));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddScoped<IPasswordHasher, T>();
        return builder;
    }

    /// <summary>
    /// Adds a scoped <see cref="IExternalIdentityValidator"/> implementation for a social/OAuth provider.
    /// Multiple validators can be registered — one per provider (e.g. Google, GitHub).
    /// </summary>
    /// <typeparam name="T">The concrete validator implementation.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithExternalIdentityValidator<T>(this IBedrockBuilder builder)
        where T : class, IExternalIdentityValidator
    {
        builder.Services.AddScoped<IExternalIdentityValidator, T>();
        return builder;
    }

    /// <summary>
    /// Replaces the default single-realm <see cref="IBedrockRealmProvider"/> with
    /// <typeparamref name="T"/>, opting this deployment into multi-realm hosting: realm-scoped
    /// overrides (MFA grace period, refresh-cookie name, refresh-token TTL, frontend base URL)
    /// resolved per request from the <c>Host</c> header, sharing ONE signing key/JWKS.
    /// </summary>
    /// <typeparam name="T">The concrete realm provider to register as singleton.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithRealmProvider<T>(this IBedrockBuilder builder)
        where T : class, IBedrockRealmProvider
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(IBedrockRealmProvider));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddSingleton<IBedrockRealmProvider, T>();
        return builder;
    }

    /// <summary>
    /// Replaces the default <see cref="IBedrockTokenIssuer"/> with a custom implementation, enabling
    /// an external IDP (e.g. OpenIddict) to sign access tokens instead of Bedrock's built-in JWT service.
    /// </summary>
    /// <remarks>
    /// Also set <c>options.Jwt.ExternalTokenIssuer = true</c> so that Bedrock skips installing its own
    /// JWT Bearer authentication scheme and does not require a signing key to be configured.
    /// </remarks>
    /// <typeparam name="T">The concrete token issuer to register as scoped.</typeparam>
    /// <param name="builder">The Bedrock builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    public static IBedrockBuilder WithTokenIssuer<T>(this IBedrockBuilder builder)
        where T : class, IBedrockTokenIssuer
    {
        var descriptor = builder.Services.FirstOrDefault(
            d => d.ServiceType == typeof(IBedrockTokenIssuer));
        if (descriptor is not null)
            builder.Services.Remove(descriptor);

        builder.Services.AddScoped<IBedrockTokenIssuer, T>();
        return builder;
    }
}
