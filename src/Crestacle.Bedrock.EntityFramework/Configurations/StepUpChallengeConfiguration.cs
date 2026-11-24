using Crestacle.Bedrock.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Crestacle.Bedrock.EntityFramework.Configurations;

internal sealed class StepUpChallengeConfiguration : IEntityTypeConfiguration<StepUpChallenge>
{
    public void Configure(EntityTypeBuilder<StepUpChallenge> builder)
    {
        builder.ToTable("step_up_challenges");

        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).HasColumnName("id");
        builder.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(e => e.Method)
            .HasColumnName("method")
            .HasMaxLength(16)
            .HasConversion<string>()
            .IsRequired();
        builder.Property(e => e.CodeHash).HasColumnName("code_hash").HasMaxLength(128);
        builder.Property(e => e.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(e => e.UsedAt).HasColumnName("used_at");
        builder.Property(e => e.IpAddress).HasColumnName("ip_address").HasMaxLength(45).IsRequired();
        builder.Property(e => e.TenantId).HasColumnName("tenant_id").HasMaxLength(64);
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").IsRequired();

        builder.Property(e => e.RowVersion)
            .HasColumnName("row_version")
            .IsRowVersion();

        builder.HasIndex(e => e.UserId)
            .HasDatabaseName("ix_step_up_challenges_user");
    }
}
