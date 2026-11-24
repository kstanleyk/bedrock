# Multi-tenancy

Bedrock supports optional multi-tenancy via the `ITenantContext` interface. When a tenant context is registered, all repository queries and writes are automatically scoped to the current tenant.

The default implementation is `NullTenantContext`, which returns `null` for all tenant identifiers — making all data globally shared. This is correct for single-tenant deployments.

---

## How it works

`BedrockContext` accepts an optional `ITenantContext` in its constructor. When present and non-null, EF Core query filters are applied to all entities, restricting reads and writes to rows belonging to the current tenant.

This means you do not need to pass a tenant ID into every repository call — the context handles isolation automatically.

---

## Implementing ITenantContext

Create a class that resolves the current tenant from your preferred source (JWT claim, subdomain, request header, etc.):

```csharp
public class JwtTenantContext : ITenantContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public JwtTenantContext(IHttpContextAccessor accessor)
    {
        _httpContextAccessor = accessor;
    }

    public string? GetTenantId() =>
        _httpContextAccessor.HttpContext?.User.FindFirst("tenant_id")?.Value;
}
```

---

## Registration

Register your implementation using the builder extension:

```csharp
builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts => { ... })
    .WithTenantContext<JwtTenantContext>()
    .AddBedrockControllers();
```

---

## Tenant-aware DbContext

If your `AppDbContext` also uses the tenant context for your own entities, pass it through the base constructor:

```csharp
public class AppDbContext : BedrockContext
{
    public AppDbContext(
        DbContextOptions<AppDbContext> options,
        ITenantContext? tenantContext = null)
        : base(options, tenantContext)
    {
    }

    public DbSet<Order> Orders { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply tenant filter to your own entities
        modelBuilder.Entity<Order>()
            .HasQueryFilter(o => o.TenantId == TenantId);
    }
}
```

---

## Sentinel multi-tenancy

Sentinel has its own `ITenantContext` interface (in `Crestacle.Sentinel.Core`). When using the `Crestacle.Bedrock.Sentinel` bridge package, a `BedrockTenantContextAdapter` is automatically registered to forward Bedrock's tenant context to Sentinel — you do not need to register a separate tenant context for Sentinel.

```csharp
builder.Services
    .AddBedrockWithSentinel<AppDbContext, AppDbContext>(
        bedrock => { ... },
        sentinel => { ... })
    .WithTenantContext<JwtTenantContext>();
    // BedrockTenantContextAdapter bridges this to Sentinel automatically
```

---

## Single-tenant deployments

No action required. The default `NullTenantContext` returns `null` for the tenant ID, and Bedrock's query filters are written to be a no-op when the tenant ID is null. All data is shared globally.
