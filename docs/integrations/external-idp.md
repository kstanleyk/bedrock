# External IDP integration

Bedrock can operate alongside an external identity provider (Auth0, Keycloak, Azure AD B2C, OpenIddict, etc.) rather than issuing its own access tokens. In this mode, Bedrock handles credential storage, MFA, passkeys, sessions, and audit — while the external IDP owns JWT issuance and validation.

---

## How it works

Setting `Jwt.ExternalTokenIssuer = true` tells Bedrock to skip installing its own JWT Bearer authentication scheme. Your application configures JWT Bearer validation against the external IDP instead.

Bedrock still requires a signing key. It uses this key internally for short-lived single-use tokens (MFA challenges, step-up tokens, enrollment tokens) that are never passed to the external IDP and never leave the service.

---

## Registration

```csharp
builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts =>
    {
        opts.Jwt.ExternalTokenIssuer = true;

        // Required: Bedrock uses this key for internal tokens only
        opts.Jwt.SigningKey = builder.Configuration["Jwt:InternalSigningKey"];

        opts.Email.FrontendBaseUrl = "https://yourapp.com";
    })
    .WithTokenIssuer<MyExternalIdpTokenIssuer>()
    .AddBedrockControllers();

// Configure JWT Bearer against your external IDP
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        opts.Authority = "https://your-idp.com";
        opts.Audience = "yourapp";
    });
```

---

## Implementing IBedrockTokenIssuer

Implement `IBedrockTokenIssuer` to delegate access token issuance to your IDP. Bedrock calls this when completing a login, MFA verification, or magic link flow:

```csharp
public class MyExternalIdpTokenIssuer : IBedrockTokenIssuer
{
    private readonly IHttpClientFactory _httpClientFactory;

    public MyExternalIdpTokenIssuer(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<AccessTokenDescriptor> IssueAccessTokenAsync(
        Guid userId,
        string email,
        IEnumerable<string> roles,
        string? tenantId,
        IDictionary<string, string>? extraClaims,
        CancellationToken ct = default)
    {
        // Call your IDP's token endpoint using the Resource Owner Password flow,
        // a custom grant, or a token exchange (RFC 8693), using userId/email/roles/
        // tenantId/extraClaims to construct the claims or subject for the IDP request.

        var client = _httpClientFactory.CreateClient("idp");
        // ... call IDP and return an AccessTokenDescriptor (token string, its unique
        // ID, and UTC expiry) so Bedrock's session layer can track revocation.
    }
}
```

`AccessTokenDescriptor` is what your implementation returns -- the token string, its unique ID (used for JTI-based revocation), and its UTC expiry.

---

## External login (OAuth/OIDC social login)

Regardless of whether `ExternalTokenIssuer` is set, Bedrock supports linking and authenticating with external OAuth/OIDC providers (Google, GitHub, etc.) via `POST auth/external-login`.

To validate provider tokens, implement `IExternalIdentityValidator` for each provider:

```csharp
public class GoogleIdentityValidator : IExternalIdentityValidator
{
    public string ProviderName => "google";

    public async Task<ExternalIdentityClaims?> ValidateAsync(
        string providerToken, CancellationToken ct = default)
    {
        // Verify the Google ID token and extract claims
        // Return null to reject
        return new ExternalIdentityClaims
        {
            ProviderUserId = payload.Subject,
            Email = payload.Email,
            DisplayName = payload.Name
        };
    }
}
```

Register each validator with the builder:

```csharp
.WithExternalIdentityValidator<GoogleIdentityValidator>()
.WithExternalIdentityValidator<GitHubIdentityValidator>()
```

Multiple validators can be registered. Bedrock selects the one matching the `provider` field in the request.

---

## Pre-validated claims login

If your IDP has already validated the provider token upstream (e.g. in an API gateway or middleware), use `LoginWithClaimsAsync` directly in your own controller rather than going through `POST auth/external-login`. This skips the validator step and trusts the claims directly.

---

## Internal tokens in external IDP mode

Even with `ExternalTokenIssuer = true`, these token flows remain internal to Bedrock and use Bedrock's own signing key:

| Token | Used for |
|---|---|
| Challenge token | Carries MFA context between `auth/login` and `auth/verify-2fa` |
| Enrollment token | Grants access to MFA setup endpoints only |
| Step-up token | Single-use; authorises sensitive operations |

These tokens are never returned as the user's access token. They are consumed internally by Bedrock's own endpoints.
