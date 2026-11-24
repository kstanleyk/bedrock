using Crestacle.Bedrock.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Crestacle.Bedrock.EntityFramework.Configurations;

internal sealed class UserCredentialConfiguration : IEntityTypeConfiguration<UserCredential>
{
    public void Configure(EntityTypeBuilder<UserCredential> builder)
    {
        builder.ToTable("user_credentials");

        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).HasColumnName("id");
        builder.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(e => e.Email).HasColumnName("email").HasMaxLength(256).IsRequired();
        builder.Property(e => e.PasswordHash).HasColumnName("password_hash").HasMaxLength(512).IsRequired();
        builder.Property(e => e.EmailConfirmed).HasColumnName("email_confirmed").IsRequired();
        builder.Property(e => e.Status)
            .HasColumnName("status")
            .HasMaxLength(32)
            .HasConversion<string>()
            .IsRequired();
        builder.Property(e => e.MfaEnabled).HasColumnName("mfa_enabled").IsRequired();
        builder.Property(e => e.MfaMethod)
            .HasColumnName("mfa_method")
            .HasMaxLength(16)
            .HasConversion<string>();
        builder.Property(e => e.TotpSecretEncrypted).HasColumnName("totp_secret_encrypted").HasMaxLength(512);
        builder.Property(e => e.TotpConfirmed).HasColumnName("totp_confirmed").IsRequired();
        builder.Property(e => e.FailedLoginAttempts).HasColumnName("failed_login_attempts").IsRequired();
        builder.Property(e => e.LockoutEnd).HasColumnName("lockout_end");
        builder.Property(e => e.IsAdminLocked).HasColumnName("is_admin_locked").IsRequired();
        builder.Property(e => e.MfaGracePeriodEndsAt).HasColumnName("mfa_grace_period_ends_at");
        builder.Property(e => e.PasswordExpiresAt).HasColumnName("password_expires_at");
        builder.Property(e => e.PasswordChangedAt).HasColumnName("password_changed_at");
        builder.Property(e => e.TenantId).HasColumnName("tenant_id").HasMaxLength(64);
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").IsRequired();
        builder.Property(e => e.UpdatedAt).HasColumnName("updated_at").IsRequired();

        builder.Property(e => e.RowVersion)
            .HasColumnName("row_version")
            .IsRowVersion();

        builder.HasIndex(e => new { e.Email, e.TenantId })
            .IsUnique()
            .HasDatabaseName("uq_user_credentials_email_tenant");

        builder.HasIndex(e => e.UserId)
            .HasDatabaseName("ix_user_credentials_user_id");
    }
}
