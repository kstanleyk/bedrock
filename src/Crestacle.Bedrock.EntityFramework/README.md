# Crestacle.Bedrock.EntityFramework

EF Core persistence layer for the Crestacle Bedrock authentication library.

## What's in this package

- **`BedrockContext`** — `DbContext` base class with pre-configured entity sets and table mappings
- **Repository implementations** — EF Core implementations of all `IXxxRepository` contracts from `Crestacle.Bedrock.Core`
- **`MemoryBedrockCache`** — `IMemoryCache`-backed implementation of `IBedrockCache` for JTI blacklisting and distributed-lock semantics
- **Health checks** — `BedrockHealthCheck` for database connectivity
- **`AddBedrockEntityFramework<TContext>()`** — DI registration extension

## Quick start

Derive your application's `DbContext` from `BedrockContext`:

```csharp
public class AppDbContext : BedrockContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}
```

Then register it:

```csharp
builder.Services.AddDbContext<AppDbContext>(...);
builder.Services.AddBedrockEntityFramework<AppDbContext>();
```

## Documentation

- [Getting started](../../docs/getting-started.md) — full setup including migrations
- [Deployment models](../../docs/deployment-models.md) — how to structure your DbContext for each model
- [Multi-tenancy](../../docs/multi-tenancy.md) — tenant isolation via `ITenantContext`
