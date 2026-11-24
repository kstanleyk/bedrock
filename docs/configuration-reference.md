# Configuration reference

All Bedrock options are configured through `BedrockOptions`, passed to `AddBedrockAspNetCore()`:

```csharp
builder.Services.AddBedrockAspNetCore(opts =>
{
    opts.Jwt.Issuer = "https://yourapp.com";
    // ...
});
```

---

## BedrockOptions

The root configuration object. All nested option objects are initialised to their defaults automatically.

| Property | Type | Description |
|---|---|---|
| `Jwt` | `JwtOptions` | JWT signing and validation settings |
| `Password` | `PasswordOptions` | Password complexity and history policy |
| `Mfa` | `MfaOptions` | MFA enrollment and grace period policy |
| `Lockout` | `LockoutOptions` | Account lockout thresholds |
| `Session` | `SessionOptions` | Concurrent session limits |
| `AnomalyDetection` | `AnomalyDetectionOptions` | Rapid IP-change detection |
| `Email` | `EmailOptions` | Frontend URLs for email links |
| `TokenExpiry` | `TokenExpiryOptions` | Lifetimes for all short-lived tokens |
| `Otp` | `OtpOptions` | OTP send-rate limits |
| `Passkey` | `PasskeyOptions` | WebAuthn/FIDO2 relying party settings |
| `IpRateLimit` | `IpRateLimitOptions` | Per-IP failed-login rate limiting |
| `ClaimsCache` | `ClaimsCacheOptions` | Optional claims enricher cache duration |

---

## JwtOptions

Controls JWT issuance and validation.

| Property | Type | Default | Notes |
|---|---|---|---|
| `Issuer` | `string` | `""` | The `iss` claim. Required. |
| `Audience` | `string` | `""` | The `aud` claim. Required. |
| `SigningKey` | `string?` | `null` | HMAC-SHA256 symmetric key (HS256). Mutually exclusive with `SigningCertificate`. |
| `SigningCertificate` | `X509Certificate2?` | `null` | RSA certificate for RS256. Mutually exclusive with `SigningKey`. |
| `PreviousSigningKey` | `string?` | `null` | Accepted during key rotation grace periods (HS256). |
| `PreviousSigningCertificate` | `X509Certificate2?` | `null` | Accepted during key rotation grace periods (RS256). |
| `AccessTokenExpiry` | `TimeSpan` | `15 minutes` | Lifetime of access tokens. |
| `RefreshTokenExpiry` | `TimeSpan` | `7 days` | Lifetime of refresh tokens. |
| `ClockSkew` | `TimeSpan` | `0` | Allowed clock drift when validating tokens. Defaults to zero (strict). |
| `ExternalTokenIssuer` | `bool` | `false` | When `true`, Bedrock skips installing its JWT Bearer scheme. Use when an external IDP owns access token issuance. See [External IDP integration](integrations/external-idp.md). |

Either `SigningKey` or `SigningCertificate` must be set unless `ExternalTokenIssuer` is `true`. `BedrockOptions.Validate()` enforces this at startup.

---

## PasswordOptions

Controls password complexity rules and history.

| Property | Type | Default | Notes |
|---|---|---|---|
| `MinLength` | `int` | `12` | Minimum password length. |
| `RequireUppercase` | `bool` | `true` | At least one uppercase letter. |
| `RequireLowercase` | `bool` | `true` | At least one lowercase letter. |
| `RequireDigit` | `bool` | `true` | At least one digit. |
| `RequireSpecialCharacter` | `bool` | `true` | At least one non-alphanumeric character. |
| `HistoryDepth` | `int` | `5` | Number of previous passwords to reject. Set to `0` to disable history checks. |
| `ExpiryDays` | `int` | `0` | Days until a password expires and must be changed. `0` means passwords never expire. |
| `CommonPasswordDenyListPath` | `string?` | `null` | Path to a newline-delimited deny-list file. Set to `"embedded"` to use the built-in top-1000 common passwords list. |

---

## MfaOptions

Controls MFA enrollment policy.

| Property | Type | Default | Notes |
|---|---|---|---|
| `Issuer` | `string` | `""` | Display name shown in TOTP authenticator apps (e.g. Google Authenticator). |
| `GracePeriodDays` | `int` | `14` | Days every user can skip enrollment before mandatory MFA is enforced, once `MandatoryRoles` is non-empty. |
| `MandatoryRoles` | `IList<string>` | `[]` | **Not per-role scoped despite the name.** A non-empty list makes MFA mandatory for *every* user — Bedrock.Core has no concept of roles to check membership against. Treat as a boolean "require MFA for everyone" switch. |
| `BackupCodeCount` | `int` | `10` | Number of single-use recovery codes generated at MFA enrolment. |

---

## LockoutOptions

Controls account lockout after failed login attempts.

| Property | Type | Default | Notes |
|---|---|---|---|
| `MaxFailedAttempts` | `int` | `5` | Failed login attempts before the account is locked. |
| `Duration` | `TimeSpan` | `15 minutes` | How long the account remains locked. |

---

## SessionOptions

Controls active session limits.

| Property | Type | Default | Notes |
|---|---|---|---|
| `MaxConcurrentSessions` | `int` | `5` | Maximum simultaneous sessions per user. The oldest session is revoked when the limit is exceeded. |
| `AbsoluteRefreshExpiry` | `TimeSpan?` | `null` | Hard cap on session lifetime, regardless of refresh activity. `null` disables this. |

---

## AnomalyDetectionOptions

Detects suspicious login patterns and triggers step-up challenges.

| Property | Type | Default | Notes |
|---|---|---|---|
| `Enabled` | `bool` | `true` | Enable or disable anomaly detection entirely. |
| `RapidIpChangeWindow` | `TimeSpan` | `10 minutes` | If a user authenticates from a different IP within this window, a step-up challenge is triggered. |

---

## EmailOptions

Configures the URLs Bedrock constructs when sending email links. All paths are appended to `FrontendBaseUrl`.

| Property | Type | Default | Notes |
|---|---|---|---|
| `FrontendBaseUrl` | `string` | `""` | Base URL of your frontend application. Required. |
| `PasswordResetPath` | `string` | `/auth/reset-password` | Path for password reset links. |
| `EmailVerificationPath` | `string` | `/auth/confirm-email` | Path for email confirmation links. |
| `EmailChangePath` | `string` | `/auth/confirm-email-change` | Path for email change confirmation links. |
| `MagicLinkPath` | `string` | `/auth/magic-link/verify` | Path for magic link verification. |
| `InvitationPath` | `string` | `/auth/accept-invitation` | Path for invitation acceptance links. |

---

## TokenExpiryOptions

Controls the lifetime of all short-lived internal tokens.

| Property | Type | Default | Notes |
|---|---|---|---|
| `ChallengeToken` | `TimeSpan` | `5 minutes` | MFA challenge token issued at login when MFA is required. |
| `StepUpToken` | `TimeSpan` | `5 minutes` | Step-up JWT issued after completing a step-up challenge. |
| `EnrollmentToken` | `TimeSpan` | `15 minutes` | Token issued to begin MFA enrolment. |
| `EmailVerificationToken` | `TimeSpan` | `24 hours` | Token sent in email verification links. |
| `PasswordResetToken` | `TimeSpan` | `1 hour` | Token sent in password reset links. |
| `OtpCode` | `TimeSpan` | `10 minutes` | Lifetime of email/SMS OTP codes. |
| `MfaChallenge` | `TimeSpan` | `5 minutes` | Lifetime of an active MFA challenge session. |
| `EmailChangeToken` | `TimeSpan` | `24 hours` | Token sent in email change confirmation links. |
| `MagicLinkToken` | `TimeSpan` | `15 minutes` | Lifetime of a magic link. |
| `Invitation` | `TimeSpan` | `72 hours` | Lifetime of a user invitation. |

---

## OtpOptions

Controls rate limiting for OTP send requests.

| Property | Type | Default | Notes |
|---|---|---|---|
| `MaxSendsPerWindow` | `int` | `5` | Maximum OTP sends per user per window. |
| `SendWindow` | `TimeSpan` | `10 minutes` | The rolling window over which sends are counted. |

---

## PasskeyOptions

Configures the WebAuthn/FIDO2 relying party. Must match your deployment origin.

| Property | Type | Default | Notes |
|---|---|---|---|
| `ServerDomain` | `string` | `"localhost"` | Relying party domain (no scheme or port). Must match the effective domain of your origin. |
| `ServerName` | `string` | `"Bedrock"` | Human-readable name shown in authenticator dialogs. |
| `Origins` | `HashSet<string>` | `["https://localhost"]` | Allowed origins for WebAuthn operations. Include all domains your frontend is served from. |
| `TimestampDriftToleranceMs` | `int` | `300000` | Allowed authenticator clock drift in milliseconds (default: 5 minutes). |

---

## IpRateLimitOptions

Limits failed login attempts from a single IP block to mitigate credential stuffing.

| Property | Type | Default | Notes |
|---|---|---|---|
| `Enabled` | `bool` | `true` | Enable or disable IP rate limiting. |
| `MaxFailedAttemptsPerIp` | `int` | `100` | Maximum failed attempts from a `/16` IP block within the window. |
| `IpLockoutWindow` | `TimeSpan` | `10 minutes` | Rolling window over which failures are counted. |
| `IpLockoutDuration` | `TimeSpan` | `15 minutes` | How long the IP block is locked out after exceeding the limit. |

---

## ClaimsCacheOptions

Controls optional caching of claims enricher results. Relevant when using a custom `IBedrockClaimsEnricher` or when Sentinel permission claims are embedded in JWTs.

| Property | Type | Default | Notes |
|---|---|---|---|
| `Duration` | `TimeSpan?` | `null` | Cache duration for enricher results. `null` disables caching (enricher is called on every request). |

Enable caching with the builder extension:

```csharp
.WithClaimsEnricherCache(TimeSpan.FromMinutes(5))
```

---

## SentinelOptions

Configured separately via `AddSentinel()`. See [Sentinel integration](integrations/sentinel.md).

| Property | Type | Default | Notes |
|---|---|---|---|
| `PermissionCacheTtl` | `TimeSpan` | `5 minutes` | How long resolved permission sets are cached in memory. |
