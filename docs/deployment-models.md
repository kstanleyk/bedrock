# Deployment models

Bedrock supports three integration patterns. Choose based on whether you want auth and business logic in the same service, or separated.

---

## Model 1: Embedded

Auth and business data live in the **same application and database**. This is the most common pattern and the one shown in the [getting started guide](getting-started.md).

```
┌──────────────────────────────────┐
│  Your Application                │
│                                  │
│  ┌──────────────┐  ┌──────────┐  │
│  │  Bedrock     │  │  Your    │  │
│  │  Controllers │  │  API     │  │
│  └──────────────┘  └──────────┘  │
│                                  │
│  ┌──────────────────────────────┐ │
│  │  Single Database             │ │
│  │  ┌──────────┐ ┌───────────┐ │ │
│  │  │ auth.*   │ │ public.*  │ │ │
│  │  │ (Bedrock)│ │ (Your app)│ │ │
│  │  └──────────┘ └───────────┘ │ │
│  └──────────────────────────────┘ │
└──────────────────────────────────┘
```

Your `DbContext` inherits `BedrockContext`, so auth tables and your business tables share the same database connection and transaction scope. Bedrock tables use the `"auth"` schema by default.

```csharp
public class AppDbContext : BedrockContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // Your business tables
    public DbSet<Order> Orders { get; set; } = null!;
    public DbSet<Product> Products { get; set; } = null!;
}
```

```csharp
builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts => { ... })
    .AddBedrockControllers();
```

**When to use:** Most applications. Simplest to operate, single migration pipeline, transactions span both auth and business operations.

---

## Model 2: Standalone auth service

Bedrock runs as a **dedicated authentication microservice** with no business data of its own. Other services validate tokens against its JWKS endpoint or forward credentials for verification.

```
┌──────────────────┐      ┌──────────────────────┐
│  Auth Service    │      │  Your API             │
│                  │      │                       │
│  Bedrock only    │◄─────│  Validates JWT        │
│  No business     │      │  against JWKS         │
│  data            │      │                       │
│                  │      │  Business data only   │
│  ┌────────────┐  │      │  ┌─────────────────┐  │
│  │  auth.*    │  │      │  │  public.*       │  │
│  │  (Bedrock) │  │      │  │  (Your app)     │  │
│  └────────────┘  │      │  └─────────────────┘  │
└──────────────────┘      └──────────────────────┘
```

Create a minimal `DbContext` with no extra entities:

```csharp
public class AuthDbContext : BedrockContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }
    // No additional DbSet<> — auth tables only
}
```

Register Bedrock as normal and mount all controllers:

```csharp
builder.Services
    .AddBedrockEntityFramework<AuthDbContext>()
    .AddBedrockAspNetCore(opts => { ... })
    .AddBedrockControllers();
```

Your other services validate tokens using the public JWKS endpoint:

```
GET /.well-known/jwks.json
```

This endpoint is served by `BedrockDiscoveryController` and is always available at the root path regardless of the `basePath` setting. Use it to configure JWT Bearer validation in your other services:

```csharp
// In your other ASP.NET Core services
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        opts.Authority = "https://auth.yourapp.com";
        opts.Audience = "yourapp";
        opts.MetadataAddress = "https://auth.yourapp.com/.well-known/jwks.json";
    });
```

**When to use:** Microservice architectures where you want a single auth boundary, or when multiple services share the same user base.

---

## Model 3: External IDP consumer

An **external identity provider** (Auth0, Keycloak, OpenIddict, Azure AD B2C) issues access tokens. Bedrock handles credential storage and optional RBAC (via Sentinel), but defers token issuance to the external IDP.

```
┌─────────────────┐      ┌──────────────────────┐
│  External IDP   │      │  Your Application    │
│  (Auth0, etc.)  │      │                      │
│                 │◄─────│  Bedrock handles:    │
│  Issues JWTs    │      │  - Credentials       │
│  Validates      │      │  - Passkeys          │
│  tokens         │      │  - MFA               │
└─────────────────┘      │  - Sentinel RBAC     │
                         │                      │
                         │  External IDP        │
                         │  handles:            │
                         │  - Token issuance    │
                         │  - Token validation  │
                         └──────────────────────┘
```

Set `ExternalTokenIssuer = true` and optionally implement `IBedrockTokenIssuer` to adapt to your IDP's token format:

```csharp
builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts =>
    {
        opts.Jwt.ExternalTokenIssuer = true;
        // SigningKey is still required — Bedrock signs internal tokens
        // (MFA challenges, step-up tokens, enrollment tokens) with its own key.
        // These never leave the service.
        opts.Jwt.SigningKey = builder.Configuration["Jwt:InternalSigningKey"];

        opts.Email.FrontendBaseUrl = "https://yourapp.com";
    })
    .WithTokenIssuer<MyExternalIdpTokenIssuer>()
    .AddBedrockControllers();
```

Implement `IBedrockTokenIssuer` to delegate access token issuance to your IDP:

```csharp
public class MyExternalIdpTokenIssuer : IBedrockTokenIssuer
{
    public Task<AccessTokenDescriptor> IssueAccessTokenAsync(
        Guid userId,
        string email,
        IEnumerable<string> roles,
        string? tenantId,
        IDictionary<string, string>? extraClaims,
        CancellationToken ct = default)
    {
        // Call your IDP's token endpoint and return an AccessTokenDescriptor
        // (token string, its unique ID, and UTC expiry).
    }
}
```

**Note on internal tokens.** Even with `ExternalTokenIssuer = true`, Bedrock still uses its own signing key for short-lived single-use tokens: MFA challenge tokens, step-up tokens, and enrollment tokens. These are internal tokens that never pass through the external IDP.

**When to use:** When your organisation already has a central IDP, or when you need standards-compliant OIDC token issuance (e.g. for third-party integrations).

---

## Choosing a model

| Question | Embedded | Standalone | External IDP |
|---|---|---|---|
| Single service? | Yes | No | Either |
| Multiple services sharing auth? | No | Yes | Yes |
| Existing IDP (Auth0, Keycloak)? | No | No | Yes |
| Need full Bedrock feature set? | Yes | Yes | Partial |
| Simplest to operate? | Yes | No | No |

If you're building a new greenfield application with one service, use **Embedded**. If you have multiple services, use **Standalone**. If you already have an IDP and want to add Bedrock's credential management on top, use **External IDP**.
