using Crestacle.Bedrock.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Crestacle.Bedrock.EntityFramework.Configurations;

internal sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).HasColumnName("id");
        builder.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(e => e.TokenHash).HasColumnName("token_hash").HasMaxLength(128).IsRequired();
        builder.Property(e => e.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").IsRequired();
        builder.Property(e => e.CreatedByIp).HasColumnName("created_by_ip").HasMaxLength(45).IsRequired();
        builder.Property(e => e.RevokedAt).HasColumnName("revoked_at");
        builder.Property(e => e.RevokedByIp).HasColumnName("revoked_by_ip").HasMaxLength(45);
        builder.Property(e => e.ReplacedByTokenHash).HasColumnName("replaced_by_token_hash").HasMaxLength(128);
        builder.Property(e => e.TenantId).HasColumnName("tenant_id").HasMaxLength(64);

        builder.Property(e => e.RowVersion)
            .HasColumnName("row_version")
            .IsRowVersion();

        builder.HasIndex(e => e.TokenHash)
            .IsUnique()
            .HasDatabaseName("uq_refresh_tokens_hash");

        builder.HasIndex(e => new { e.UserId, e.RevokedAt, e.ExpiresAt })
            .HasDatabaseName("ix_refresh_tokens_user_active");
    }
}
