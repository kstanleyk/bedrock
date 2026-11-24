using Crestacle.Bedrock.Core.Defaults;
using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.EntityFramework.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Crestacle.Bedrock.EntityFramework;

public class BedrockContext : DbContext
{
    private readonly ITenantContext _tenantContext;

    private string? CurrentTenantId => _tenantContext.GetTenantId();

    public BedrockContext(DbContextOptions options, ITenantContext? tenantContext = null)
        : base(options)
    {
        _tenantContext = tenantContext ?? new NullTenantContext();
    }

    public DbSet<UserCredential> UserCredentials { get; set; } = null!;
    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;
    public DbSet<MfaChallenge> MfaChallenges { get; set; } = null!;
    public DbSet<StepUpChallenge> StepUpChallenges { get; set; } = null!;
    public DbSet<OtpCode> OtpCodes { get; set; } = null!;
    public DbSet<RecoveryCode> RecoveryCodes { get; set; } = null!;
    public DbSet<Session> Sessions { get; set; } = null!;
    public DbSet<KnownDevice> KnownDevices { get; set; } = null!;
    public DbSet<PasswordHistory> PasswordHistories { get; set; } = null!;
    public DbSet<EmailVerificationToken> EmailVerificationTokens { get; set; } = null!;
    public DbSet<PasswordResetToken> PasswordResetTokens { get; set; } = null!;
    public DbSet<AuditEntry> AuditEntries { get; set; } = null!;
    public DbSet<ConsentRecord> ConsentRecords { get; set; } = null!;
    public DbSet<EmailChangeToken> EmailChangeTokens { get; set; } = null!;
    public DbSet<MagicLinkToken> MagicLinkTokens { get; set; } = null!;
    public DbSet<PasskeyCredential> PasskeyCredentials { get; set; } = null!;
    public DbSet<ExternalIdentity> ExternalIdentities { get; set; } = null!;
    public DbSet<Invitation> Invitations { get; set; } = null!;
    public DbSet<ApiKey> ApiKeys { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasDefaultSchema("auth");
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(BedrockEntityFrameworkAssemblyMarker).Assembly);

        ApplyUtcConverters(modelBuilder);
        ApplyTenantFilters(modelBuilder);

        // UserCredentialConfiguration/SessionConfiguration/RefreshTokenConfiguration's
        // IsRowVersion() is a genuine, DB-enforced optimistic-concurrency token only on SQL
        // Server, where the native rowversion/timestamp column type auto-increments on every
        // write. PostgreSQL has no
        // equivalent for a plain byte[] column -- nothing in the database ever changes its
        // value, so the "concurrency check" would be a silent no-op there (see
        // docs/quality-roadmap.md D5). Auto-detected (not an opt-in extension method a consumer
        // has to remember to call) so this can never silently regress to the no-op state the
        // way Crestacle.Sentinel.EntityFramework's equivalent UseSentinelPostgreSqlConcurrency()
        // did -- that one has zero callers anywhere in this solution.
        // Checked by provider name string, not Database.IsNpgsql() -- that extension method
        // lives in the Npgsql.EntityFrameworkCore.PostgreSQL package, and this project
        // deliberately has no package reference to any specific EF Core provider (a SQL-Server-
        // or SQLite-only consumer shouldn't have to pull in Npgsql transitively).
        if (Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL")
            UseNpgsqlXminConcurrency(modelBuilder);
    }

    private static void UseNpgsqlXminConcurrency(ModelBuilder modelBuilder)
    {
        // xmin is a PostgreSQL system column (type xid = uint) that increments on every row
        // update -- mapping it as a shadow concurrency token is the real, DB-enforced
        // equivalent of SQL Server's IsRowVersion().
        foreach (var entityType in new[] { typeof(UserCredential), typeof(Session), typeof(RefreshToken) })
        {
            modelBuilder.Entity(entityType)
                .Property<uint>("xmin")
                .HasColumnType("xid")
                .ValueGeneratedOnAddOrUpdate()
                .IsConcurrencyToken();

            // Without this, IsRowVersion() from the default configuration still generates a
            // `row_version bytea NOT NULL` column -- but PostgreSQL has no mechanism to
            // auto-populate it on INSERT, which would be a null-constraint violation on every
            // insert. xmin handles concurrency natively; the bytea column is redundant and
            // harmful once xmin is in play.
            modelBuilder.Entity(entityType).Ignore(nameof(UserCredential.RowVersion));
        }
    }

    private static void ApplyUtcConverters(ModelBuilder modelBuilder)
    {
        var utcConverter = new UtcDateTimeConverter();
        var nullableUtcConverter = new NullableUtcDateTimeConverter();

        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                if (property.ClrType == typeof(DateTime))
                    property.SetValueConverter(utcConverter);
                else if (property.ClrType == typeof(DateTime?))
                    property.SetValueConverter(nullableUtcConverter);
            }
        }
    }

    private void ApplyTenantFilters(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserCredential>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<RefreshToken>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<MfaChallenge>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<StepUpChallenge>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<OtpCode>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<RecoveryCode>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<Session>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<KnownDevice>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<PasswordHistory>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<EmailVerificationToken>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<PasswordResetToken>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<AuditEntry>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<ConsentRecord>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<EmailChangeToken>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<MagicLinkToken>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<PasskeyCredential>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<ExternalIdentity>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<Invitation>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);

        modelBuilder.Entity<ApiKey>().HasQueryFilter(
            e => CurrentTenantId == null || e.TenantId == CurrentTenantId || e.TenantId == null);
    }
}
