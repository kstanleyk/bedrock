using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Crestacle.Sentinel.EntityFramework.Configurations;

internal sealed class AuditEntryConfiguration : IEntityTypeConfiguration<AuditEntry>
{
    public void Configure(EntityTypeBuilder<AuditEntry> builder)
    {
        builder.ToTable("audit_log", "rbac");

        builder.HasKey(a => a.Id);

        // Store action as its string name so the log is self-documenting without a lookup table.
        builder.Property(a => a.Action)
               .HasConversion<string>()
               .HasMaxLength(50)
               .IsRequired();

        builder.Property(a => a.EntityId)
               .HasMaxLength(200)
               .IsRequired();

        builder.Property(a => a.ActorIdentityId)
               .HasMaxLength(256)
               .IsRequired();

        builder.Property(a => a.ActorIp)
               .HasMaxLength(45);   // longest IPv6 representation

        builder.Property(a => a.ActorUserAgent)
               .HasMaxLength(512);

        builder.Property(a => a.CreatedOn)
               .IsRequired();

        // Null means single-tenant / unfiltered, per ITenantContext's own doc comment — the same
        // convention as every other Sentinel entity's TenantId (e.g. UserRole.TenantId).
        builder.Property(a => a.TenantId)
               .HasMaxLength(100);

        // Append-only: no updates, no deletes via EF.
        // Enforce at the DB level with a trigger or restrictive role — at the EF level we
        // simply never expose a mutating method on the table.
        builder.HasIndex(a => a.ActorIdentityId);
        builder.HasIndex(a => a.CreatedOn);
        builder.HasIndex(a => a.TenantId);
    }
}
