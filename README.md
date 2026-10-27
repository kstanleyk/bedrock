# Crestacle Bedrock

Bedrock is a modular authentication and authorization library for ASP.NET Core. It provides a complete, production-ready identity stack — user registration, login, MFA, passkeys, API keys, sessions, and audit — that you integrate into your application rather than building from scratch.

The companion library [Crestacle.Sentinel](docs/integrations/sentinel.md) adds role-based access control (RBAC) on top of Bedrock's identity layer.

**Version:** 1.4.2 | **Target frameworks:** .NET 10, .NET 8 | **License:** MIT

---

## Packages

| Package | Purpose |
|---|---|
| `Crestacle.Bedrock.Core` | Domain entities, interfaces, and options. No runtime dependencies beyond DI abstractions. |
| `Crestacle.Bedrock.AspNetCore` | Controllers, middleware, JWT, Argon2 hashing, MFA/TOTP, FIDO2 passkeys. |
| `Crestacle.Bedrock.EntityFramework` | EF Core repositories and `BedrockContext` base class. |
| `Crestacle.Bedrock.Redis` | Redis-backed distributed cache for multi-pod deployments. |
| `Crestacle.Bedrock.HaveIBeenPwned` | Breached-password detection via the HIBP k-anonymity API. |
| `Crestacle.Sentinel.Core` | RBAC domain layer — roles, permissions, entities. |
| `Crestacle.Sentinel.AspNetCore` | `[MustHavePermission]` attribute and dynamic policy provider. |
| `Crestacle.Sentinel.EntityFramework` | EF Core RBAC repositories. |
| `Crestacle.Bedrock.Sentinel` | Bridge package — unified DI registration for Bedrock + Sentinel together. |

---

## Quick start

```bash
dotnet add package Crestacle.Bedrock.AspNetCore
dotnet add package Crestacle.Bedrock.EntityFramework
```

```csharp
// 1. Inherit BedrockContext to add auth tables to your database
public class AppDbContext : BedrockContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    // Add your own DbSet<> properties here
}

// 2. Register in Program.cs
builder.Services.AddDbContext<AppDbContext>(opts =>
    opts.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts =>
    {
        opts.Jwt.Issuer = "https://yourapp.com";
        opts.Jwt.Audience = "yourapp";
        opts.Jwt.SigningKey = builder.Configuration["Jwt:SigningKey"];
        opts.Email.FrontendBaseUrl = "https://yourapp.com";
    })
    .WithEmailSender<YourEmailSender>()
    .AddBedrockControllers();

// 3. Add middleware
app.UseBedrock();
app.MapControllers();
```

All auth endpoints are now available under `api/bedrock/` — see the [API reference](docs/api-reference.md).

---

## Documentation

- [Getting started](docs/getting-started.md) — complete walkthrough from install to first login
- [Deployment models](docs/deployment-models.md) — embedded, standalone, or external IDP
- [Architecture](docs/architecture.md) — package structure and design decisions
- [Configuration reference](docs/configuration-reference.md) — all options with defaults
- [API reference](docs/api-reference.md) — all HTTP endpoints
- [Security guide](docs/security.md) — production hardening checklist
- [Multi-tenancy](docs/multi-tenancy.md) — tenant isolation setup
- [Quality roadmap](docs/quality-roadmap.md) — known defects and the phased plan to close them
- [Features roadmap](docs/features-roadmap.md) — capability gaps and proposed additions

### Integrations

- [Sentinel RBAC](docs/integrations/sentinel.md)
- [Redis distributed cache](docs/integrations/redis.md)
- [Have I Been Pwned](docs/integrations/hibp.md)
- [External identity providers](docs/integrations/external-idp.md)
- [OpenIddict](docs/integrations/openiddict.md)

## Samples

Runnable sample projects, one per deployment model. Each uses SQLite — no external database needed.

| Sample | Model |
|---|---|
| [samples/Embedded](samples/Embedded/) | Auth and business data in one app |
| [samples/Standalone](samples/Standalone/) | Dedicated auth microservice |
| [samples/ExternalIdp](samples/ExternalIdp/) | Bedrock + external token issuer |

```bash
cd samples/Embedded && dotnet run
```
