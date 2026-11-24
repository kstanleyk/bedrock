# Getting started

This guide walks through installing Bedrock, wiring it into an ASP.NET Core application, running migrations, and making a first authenticated request.

---

## Prerequisites

- .NET 10
- An EF Core-compatible database (PostgreSQL, SQL Server, SQLite, etc.)
- An SMTP provider or custom email sender (required for email verification and password reset)

---

## 1. Install packages

At minimum you need the ASP.NET Core and EntityFramework packages:

```bash
dotnet add package Crestacle.Bedrock.AspNetCore
dotnet add package Crestacle.Bedrock.EntityFramework
```

Optional packages:

```bash
dotnet add package Crestacle.Bedrock.Redis          # Distributed cache (multi-pod)
dotnet add package Crestacle.Bedrock.HaveIBeenPwned # Breached password detection
dotnet add package Crestacle.Bedrock.Sentinel        # RBAC (includes Sentinel packages)
```

---

## 2. Create your DbContext

Inherit from `BedrockContext` to add all auth tables to your database. You can add your own `DbSet<>` properties alongside Bedrock's:

```csharp
public class AppDbContext : BedrockContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // Your application's own tables go here
    public DbSet<Product> Products { get; set; } = null!;
}
```

Bedrock tables are created in the `"auth"` schema by default, keeping them separate from your application tables even when sharing a single database.

---

## 3. Register services

In `Program.cs`:

```csharp
// Register your DbContext
builder.Services.AddDbContext<AppDbContext>(opts =>
    opts.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

// Register Bedrock
builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts =>
    {
        // JWT settings — required
        opts.Jwt.Issuer = "https://yourapp.com";
        opts.Jwt.Audience = "yourapp";
        opts.Jwt.SigningKey = builder.Configuration["Jwt:SigningKey"];

        // Frontend URL — required for email links
        opts.Email.FrontendBaseUrl = "https://yourapp.com";

        // MFA issuer — shown in authenticator apps
        opts.Mfa.Issuer = "Your App";

        // Passkey — update for production
        opts.Passkey.ServerDomain = "yourapp.com";
        opts.Passkey.ServerName = "Your App";
        opts.Passkey.Origins = ["https://yourapp.com"];
    })
    .WithEmailSender<YourEmailSender>()  // Implement IEmailSender
    .AddBedrockControllers();
```

`AddBedrockEntityFramework<T>()` must be called before `AddBedrockAspNetCore()`.

---

## 4. Add middleware

```csharp
app.UseBedrock();
app.MapControllers();
```

`UseBedrock()` adds, in order:
1. Exception-to-HTTP mapping middleware
2. `UseRouting()`
3. `UseAuthentication()` (JWT Bearer)
4. API key authentication middleware
5. `UseAuthorization()`
6. Token scope enforcement middleware

Place `UseBedrock()` before any middleware that needs the authenticated user.

Bedrock's own exception middleware (step 1 above) catches every exception — including non-Bedrock
ones — and returns a structured 500 with no leaked message or stack trace, so a request routed
through `UseBedrock()` is already covered. For real deployments, also register ASP.NET Core's own
catch-all for anything outside that pipeline (startup failures, middleware you add ahead of
`UseBedrock()`, endpoints that bypass it):

```csharp
if (!app.Environment.IsDevelopment())
    app.UseExceptionHandler("/error");
```

with a minimal `/error` endpoint that returns a generic `500`. See `samples/*/Program.cs` for the
pattern used in this repo's sample apps.

---

## 5. Run migrations

Bedrock entity configurations are applied automatically when your `AppDbContext` inherits from `BedrockContext`. Add and run a migration as normal:

```bash
dotnet ef migrations add InitialCreate --context AppDbContext
dotnet ef database update --context AppDbContext
```

---

## 6. Implement IEmailSender

Bedrock uses `IEmailSender` for verification emails, password resets, magic links, and invitations. The default is a no-op. Implement the interface using your SMTP provider:

```csharp
public class SmtpEmailSender : IEmailSender
{
    public Task SendEmailVerificationAsync(string toEmail, string verificationUrl, CancellationToken ct = default)
        => SendAsync(toEmail, "Verify your email", $"Click to verify: {verificationUrl}", ct);

    public Task SendPasswordResetAsync(string toEmail, string resetUrl, CancellationToken ct = default)
        => SendAsync(toEmail, "Reset your password", $"Click to reset: {resetUrl}", ct);

    public Task SendAccountLockedAsync(string toEmail, DateTime lockoutEnd, CancellationToken ct = default)
        => SendAsync(toEmail, "Account locked", $"Your account is locked until {lockoutEnd:u}.", ct);

    public Task SendMfaOtpAsync(string toEmail, string code, CancellationToken ct = default)
        => SendAsync(toEmail, "Your verification code", $"Your code is: {code}", ct);

    public Task SendAsync(string toEmail, string subject, string htmlBody, CancellationToken ct = default)
    {
        // Send using your SMTP client
    }

    public Task SendEmailChangeVerificationAsync(string newEmail, string confirmationUrl, CancellationToken ct = default)
        => SendAsync(newEmail, "Confirm your new email", $"Click to confirm: {confirmationUrl}", ct);

    public Task SendEmailChangeNotificationAsync(string oldEmail, CancellationToken ct = default)
        => SendAsync(oldEmail, "Email change requested", "A change to your account's email address was requested.", ct);

    public Task SendMagicLinkAsync(string toEmail, string magicLinkUrl, CancellationToken ct = default)
        => SendAsync(toEmail, "Your login link", $"Click to log in: {magicLinkUrl}", ct);
}
```

Register it with `.WithEmailSender<SmtpEmailSender>()`.

---

## 7. First request — register and log in

With the server running, register a user:

```http
POST /api/bedrock/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "CorrectHorseBatteryStaple1!"
}
```

Confirm the email using the token sent to the user's inbox, then log in:

```http
POST /api/bedrock/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "CorrectHorseBatteryStaple1!"
}
```

A successful login returns:

```json
{
  "success": true,
  "data": {
    "accessToken": "eyJ...",
    "refreshToken": "...",
    "accessTokenExpiresAt": "2025-01-01T00:15:00Z",
    "requiresMfa": false
  }
}
```

Use the `accessToken` as a Bearer token for subsequent requests:

```http
GET /api/bedrock/sessions
Authorization: Bearer eyJ...
```

---

## Configuration checklist

Before going to production, review the [security guide](security.md). The most critical items are:

- Use a strong, randomly-generated `Jwt.SigningKey` (32+ characters) or an RS256 certificate
- Set `Email.FrontendBaseUrl` to your production domain
- Update `Passkey.ServerDomain` and `Passkey.Origins` if using passkeys
- Wire up a real `IEmailSender`
- Consider adding Redis for multi-pod deployments (see [Redis integration](integrations/redis.md))
- Consider adding HIBP breach detection (see [HIBP integration](integrations/hibp.md))
