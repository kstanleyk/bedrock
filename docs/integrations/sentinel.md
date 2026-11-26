# Sentinel RBAC integration

Sentinel is a role-based access control (RBAC) library that integrates with Bedrock to add permissions and roles to your application. It is distributed as a separate set of packages and connected to Bedrock via the `Crestacle.Bedrock.Sentinel` bridge package.

---

## Packages

```bash
dotnet add package Crestacle.Bedrock.Sentinel
```

This meta-package includes `Crestacle.Sentinel.Core`, `Crestacle.Sentinel.AspNetCore`, and `Crestacle.Sentinel.EntityFramework`.

---

## Database setup

Sentinel stores roles and permissions in its own schema. You can share a single `DbContext` with Bedrock, or use separate contexts.

### Shared context (recommended for most applications)

Have your `DbContext` inherit `BedrockContext` and also implement `IAuthDbContext`. `IAuthDbContext`
requires these exact members:

```csharp
public class AppDbContext : BedrockContext, IAuthDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // Sentinel tables
    public DbSet<User>               Users               => Set<User>();
    public DbSet<Role>                Roles               => Set<Role>();
    public DbSet<Permission>         Permissions         => Set<Permission>();
    public DbSet<UserRole>           UserRoles           => Set<UserRole>();
    public DbSet<RolePermission>     RolePermissions     => Set<RolePermission>();
    public DbSet<AuditEntry>         AuditLog            => Set<AuditEntry>();
    public DbSet<PermissionConflict> PermissionConflicts => Set<PermissionConflict>();
    public DbSet<PendingAssignment>  PendingAssignments  => Set<PendingAssignment>();
}
```

Note that Sentinel's `Core.Entities.User` is its own entity -- the Sentinel RBAC identity (keyed on
`IdentityId`, a bridge key to Bedrock's own user record) -- not a reuse of a Bedrock type.

### Separate context

If you prefer Sentinel data in its own database or context:

```csharp
public class SentinelDbContext : DbContext, IAuthDbContext
{
    public SentinelDbContext(DbContextOptions<SentinelDbContext> options)
        : base(options) { }

    public DbSet<User> Users { get; set; } = null!;
    // ... remaining IAuthDbContext DbSets, same as above
}
```

---

## Registration

### Combined registration (simplest)

```csharp
builder.Services
    .AddBedrockWithSentinel<AppDbContext, AppDbContext>(
        bedrock =>
        {
            bedrock.Jwt.Issuer = "https://yourapp.com";
            bedrock.Jwt.Audience = "yourapp";
            bedrock.Jwt.SigningKey = builder.Configuration["Jwt:SigningKey"];
            bedrock.Email.FrontendBaseUrl = "https://yourapp.com";
        },
        sentinel =>
        {
            sentinel.PermissionCacheTtl = TimeSpan.FromMinutes(5);
        })
    .WithPermissionClaims()  // Embeds permissions into JWTs
    .WithEmailSender<YourEmailSender>()
    .AddBedrockControllers();
```

When both context type parameters are the same (`AppDbContext, AppDbContext`), a single context is used for both Bedrock and Sentinel tables.

### Separate registration

```csharp
builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts => { ... })
    .AddSentinel<SentinelDbContext>(opts =>
    {
        opts.PermissionCacheTtl = TimeSpan.FromMinutes(10);
    })
    .WithPermissionClaims()
    .AddBedrockControllers();
```

---

## Using permissions in your API

Apply the `[MustHavePermission]` attribute to controllers or actions, passing a feature and an
action rather than a single permission string:

```csharp
[MustHavePermission("Order", AppAction.Read)]
[HttpGet("orders")]
public IActionResult GetOrders() { ... }

[MustHavePermission("Order", AppAction.Create)]
[HttpPost("orders")]
public IActionResult CreateOrder() { ... }
```

`AppAction` (`Crestacle.Sentinel.Core.Authorization`) provides the standard CRUD actions
(`Create`, `Read`, `Update`, `Delete`); the feature is any string your app chooses to register in
its permission registry. `SentinelFeature` provides the three feature names Sentinel's own
built-in management endpoints use (`User`, `Role`, `Audit`) if you need to gate your own
endpoints alongside them. The attribute resolves these to a permission ID of the form
`Permission.{Feature}.{Action}` and generates a dynamic ASP.NET Core policy for it -- you do not
need to register policies manually.

---

## Embedding permissions in JWTs

When `.WithPermissionClaims()` is called, Sentinel's `SentinelClaimsEnricher` is registered as the `IBedrockClaimsEnricher`. It adds the user's resolved permission set as claims inside the JWT, so downstream services can authorise requests without a database call.

Enable claims caching to avoid re-resolving permissions on every request:

```csharp
.WithPermissionClaims()
.WithClaimsEnricherCache(TimeSpan.FromMinutes(5))
```

Each granted permission is added as its own flat claim (not nested under a single array key),
along with a `name` and an `mfa_enabled` claim:

```json
{
  "sub": "...",
  "Permission.Order.Read": "true",
  "Permission.Order.Create": "true",
  "name": "Jane Doe",
  "mfa_enabled": "true"
}
```

**Token size:** every permission adds ~40–60 bytes. Apps with large permission sets have hit
reverse-proxy default header-buffer limits this way in production — see "Embedding only profile
claims" below for the lighter alternative.

---

## Embedding only profile claims (no permissions)

If your app needs the caller's name, MFA status, and role on every token, but does not want one
claim per granted permission inflating token size, call `.WithProfileClaims()` instead of
`.WithPermissionClaims()`:

```csharp
builder.Services
    .AddBedrockWithSentinel<AppDbContext, AppDbContext>(bedrock => { ... })
    .WithProfileClaims()   // name + mfa_enabled + role claims, no Permission.* claims
    .AddBedrockControllers();
```

This registers `SentinelProfileClaimsEnricher` instead of `SentinelClaimsEnricher` as the
`IBedrockClaimsEnricher`. The resulting token carries exactly:

```json
{
  "sub": "...",
  "name": "Jane Doe",
  "mfa_enabled": "true"
}
```

— plus role claims from `GetRolesAsync`, same as `.WithPermissionClaims()`. `[MustHavePermission]`
still works either way: it resolves permissions from the database (cached), never from claims.

`.WithPermissionClaims()` and `.WithProfileClaims()` are mutually exclusive — both replace the
single registered `IBedrockClaimsEnricher`, so whichever is called last wins. Calling neither
leaves the default `NullBedrockClaimsEnricher` in place: no `name`, `mfa_enabled`, or role claims
at all, and nothing but the baseline `sub`/`user_id`/`email`/`roles` (empty)/`token_type` claims
`JwtService` always adds. **This is an easy trap**: if your app's own `ICurrentUserService` or
frontend reads `name`/`mfa_enabled`/a role claim expecting it to be populated, and you call
neither `With*Claims()` method, those fields are silently empty on every token, with no error at
login — the symptom shows up downstream (a crash on `user.name`, or a branch-scoping check that
treats "no role claim" as unrestricted access) rather than at the point the gap was introduced.
If you only need permissions back-channel, use `GET api/auth/profile/me` (below) instead of
either method — it requires no enricher at all.

### `GET api/auth/profile/me`

Returns the caller's profile from the database regardless of what the access token carries —
use this if you'd rather not put profile data in the JWT at all, or as a fallback for clients
that predate adding `.WithProfileClaims()`/`.WithPermissionClaims()`. Requires only
`[Authorize]`, same as `GET api/auth/permissions/me`. See `docs/api-reference.md` for the
response shape.

---

## SentinelOptions

| Property | Type | Default | Notes |
|---|---|---|---|
| `PermissionCacheTtl` | `TimeSpan` | `5 minutes` | How long resolved permission sets are cached in-process. |

For multi-pod deployments, replace `MemoryPermissionCache` with a distributed implementation.

---

## Migrations

Sentinel entity configurations are applied through `IAuthDbContext`. Run migrations as normal after adding the `IAuthDbContext` DbSets to your context:

```bash
dotnet ef migrations add AddSentinel --context AppDbContext
dotnet ef database update --context AppDbContext
```
