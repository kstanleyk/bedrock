using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.EntityFramework.Caching;
using Crestacle.Bedrock.EntityFramework.Repositories;
using Microsoft.Extensions.DependencyInjection;

namespace Crestacle.Bedrock.EntityFramework.Extensions;

public static class BedrockEntityFrameworkServiceCollectionExtensions
{
    /// <summary>
    /// Registers Bedrock EF Core repositories, unit-of-work, and the in-memory cache
    /// implementation for a host application that supplies its own <typeparamref name="TContext"/>.
    /// </summary>
    /// <typeparam name="TContext">
    /// The application's <see cref="BedrockContext"/>-derived DbContext. The caller is
    /// responsible for registering <typeparamref name="TContext"/> and configuring its
    /// <see cref="Microsoft.EntityFrameworkCore.DbContextOptions"/> — including any execution
    /// strategy for transient-fault retry resilience.
    /// </typeparam>
    /// <remarks>
    /// <para>
    /// <b>⚠ Important — transient fault resilience is the caller's responsibility.</b>
    /// Bedrock cannot configure an EF Core execution strategy because it does not own
    /// <see cref="Microsoft.EntityFrameworkCore.DbContextOptions"/> registration.
    /// Without an execution strategy, a transient database connection drop during a
    /// login or token refresh will surface as an unhandled exception to the caller.
    /// Configure retries when you register your DbContext (see examples below).
    /// </para>
    /// <para><b>Retry resilience (recommended for production)</b></para>
    /// <para>
    /// Configure retries when you register your context:
    /// </para>
    /// <para><b>SQL Server</b></para>
    /// <code>
    /// services.AddDbContext&lt;AppDbContext&gt;(options =&gt;
    ///     options.UseSqlServer(connectionString, sql =&gt;
    ///         sql.EnableRetryOnFailure(
    ///             maxRetryCount: 6,
    ///             maxRetryDelay: TimeSpan.FromSeconds(30),
    ///             errorNumbersToAdd: null)));
    /// </code>
    /// <para><b>PostgreSQL (Npgsql)</b></para>
    /// <para>
    /// Npgsql provides a built-in retry strategy. Set <c>Max Auto Prepare</c> and the retry
    /// count in your connection string or via <c>UseNpgsql</c>:
    /// </para>
    /// <code>
    /// services.AddDbContext&lt;AppDbContext&gt;(options =&gt;
    ///     options.UseNpgsql(connectionString, npgsql =&gt;
    ///         npgsql.EnableRetryOnFailure(maxRetryCount: 6)));
    /// </code>
    /// <para><b>Production cache resilience and multi-pod deployments</b></para>
    /// <para>
    /// The default <see cref="MemoryBedrockCache"/> is process-local and suitable for
    /// single-node or development use. In a horizontally scaled deployment it has two
    /// important limitations:
    /// <list type="bullet">
    ///   <item>
    ///     <c>MaxConcurrentSessions</c> enforcement relies on <c>TryAcquireLockAsync</c>,
    ///     whose internal <c>lock</c> gate does not span pods. Two pods can simultaneously
    ///     allow session creation for the same user, silently exceeding the configured limit.
    ///   </item>
    ///   <item>
    ///     JTI blacklist entries written by one pod are invisible to other pods until the
    ///     token's natural expiry.
    ///   </item>
    /// </list>
    /// Replace <see cref="MemoryBedrockCache"/> with a Redis-backed
    /// <see cref="Crestacle.Bedrock.Core.Interfaces.Services.IBedrockCache"/> that provides
    /// atomic NX semantics (e.g. <c>SET key value NX PX ttl</c>) to restore correct
    /// behaviour in multi-pod deployments. The replacement should also encapsulate its own
    /// retry and circuit-breaker policies so transient broker failures do not propagate as
    /// unhandled exceptions.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddBedrockEntityFramework<TContext>(
        this IServiceCollection services)
        where TContext : BedrockContext
    {
        // Forward the concrete context so repositories can inject BedrockContext directly.
        if (typeof(TContext) != typeof(BedrockContext))
        {
            services.AddScoped<BedrockContext>(sp =>
                (BedrockContext)(object)sp.GetRequiredService<TContext>());
        }

        services.AddScoped<IBedrockUnitOfWork, BedrockUnitOfWork>();

        services.AddScoped<ICredentialRepository, CredentialRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IMfaChallengeRepository, MfaChallengeRepository>();
        services.AddScoped<IStepUpChallengeRepository, StepUpChallengeRepository>();
        services.AddScoped<IOtpCodeRepository, OtpCodeRepository>();
        services.AddScoped<IRecoveryCodeRepository, RecoveryCodeRepository>();
        services.AddScoped<ISessionRepository, SessionRepository>();
        services.AddScoped<IKnownDeviceRepository, KnownDeviceRepository>();
        services.AddScoped<IPasswordHistoryRepository, PasswordHistoryRepository>();
        services.AddScoped<IEmailVerificationTokenRepository, EmailVerificationTokenRepository>();
        services.AddScoped<IPasswordResetTokenRepository, PasswordResetTokenRepository>();
        services.AddScoped<IAuditRepository, AuditRepository>();
        services.AddScoped<IConsentRepository, ConsentRepository>();
        services.AddScoped<IEmailChangeTokenRepository, EmailChangeTokenRepository>();
        services.AddScoped<IMagicLinkTokenRepository, MagicLinkTokenRepository>();
        services.AddScoped<IPasskeyCredentialRepository, PasskeyCredentialRepository>();
        services.AddScoped<IExternalIdentityRepository, ExternalIdentityRepository>();
        services.AddScoped<IInvitationRepository, InvitationRepository>();
        services.AddScoped<IApiKeyRepository, ApiKeyRepository>();

        services.AddMemoryCache();
        // Singleton, not Scoped: TryAcquireLockAsync's correctness depends on _lockGate being
        // the SAME object across concurrent callers (see its own class remarks). A Scoped
        // registration gives every request its own MemoryBedrockCache instance -- and its own
        // fresh _lockGate -- so the lock statement never actually serializes two concurrent
        // requests against each other, silently defeating the documented single-node NX-gate
        // guarantee (MaxConcurrentSessions enforcement, JTI-blacklist atomicity) even within
        // one process. IMemoryCache itself is already Singleton; this has no scoped dependency
        // of its own, so Singleton is safe.
        services.AddSingleton<IBedrockCache, MemoryBedrockCache>();

        return services;
    }
}
