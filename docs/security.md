# Security guide

This page describes Bedrock's security defaults and what you should review before going to production.

---

## Secure defaults

The following are enabled and hardened out of the box. You should not disable them without a specific reason.

**Password hashing.** Passwords are hashed with Argon2id. The `IPasswordHasher` interface is available for replacement, but Argon2id is strongly recommended.

**Clock skew.** JWT validation clock skew defaults to zero. This prevents tokens from being valid beyond their stated expiry due to clock drift. Only increase this if your deployment has unavoidable clock drift.

**Account lockout.** Accounts lock after 5 failed login attempts for 15 minutes. Adjust `LockoutOptions` if needed, but do not disable.

**IP rate limiting.** After 100 failed attempts from a `/16` IP block within 10 minutes, that block is locked out for 15 minutes. This is enabled by default (`IpRateLimit.Enabled = true`).

**Anomaly detection.** Rapid IP changes within 10 minutes trigger a step-up challenge. This is enabled by default (`AnomalyDetection.Enabled = true`).

**Token scope enforcement.** Enrollment tokens cannot be used on regular endpoints. The `BedrockScopeMiddleware` enforces this at the HTTP layer.

**TOTP replay prevention.** TOTP codes cannot be reused within their validity window.

**Session concurrency limits.** A user can have at most 5 concurrent sessions by default. The oldest is revoked when the limit is exceeded.

---

## Production checklist

### JWT signing key

Use a randomly generated key of at least 32 characters. Do not use a predictable or short key.
This minimum length is enforced at startup — `BedrockOptions.Validate()` throws an
`InvalidOperationException` if `Jwt.SigningKey` is set but shorter than 32 characters, so a
weak HS256 key fails fast instead of just being discouraged by this doc. The check only
applies to the HS256 `SigningKey` path; an RS256 `SigningCertificate` is not length-checked.

```bash
# Generate a suitable key
openssl rand -base64 32
```

Store the key in a secrets manager (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault) — not in `appsettings.json` committed to source control.

For higher security, prefer RS256 (asymmetric) over HS256 (symmetric). With RS256, the private key never needs to leave the auth service:

```csharp
opts.Jwt.SigningCertificate = X509Certificate2.CreateFromPemFile(
    "/certs/signing.crt", "/certs/signing.key");
```

### Key rotation

Bedrock supports zero-downtime key rotation via the `PreviousSigningKey` / `PreviousSigningCertificate` fields. During the rotation window both keys are accepted for validation, while new tokens are signed with the new key:

```csharp
opts.Jwt.SigningKey = newKey;
opts.Jwt.PreviousSigningKey = oldKey;  // Remove after all old tokens expire
```

### HTTPS

Bedrock does not enforce HTTPS — that is the responsibility of your hosting infrastructure. Ensure all endpoints are served over TLS in production. Passkeys require HTTPS and will not work over plain HTTP.

### Passkey origins

The `PasskeyOptions.Origins` set must exactly match the origins your frontend is served from. An incorrect value will cause all passkey registrations and authentications to fail. Update from the default `"https://localhost"` before deploying:

```csharp
opts.Passkey.ServerDomain = "yourapp.com";
opts.Passkey.Origins = ["https://yourapp.com", "https://www.yourapp.com"];
```

### Distributed cache

The default in-memory cache (`MemoryBedrockCache`) does not share state across multiple pods. In a multi-pod deployment, use Redis to ensure JTI blacklisting, IP rate limiting, OTP limits, and session locks work correctly across all instances. See [Redis integration](integrations/redis.md).

### Email sender

The default `IEmailSender` is a no-op. Without a real implementation, email verification, password reset, magic links, and invitations will silently do nothing. Wire up a real sender before deploying.

### Common password deny-list

Enable the built-in deny-list to block the most commonly used passwords:

```csharp
opts.Password.CommonPasswordDenyListPath = "embedded";
```

For stronger protection, also enable HIBP breach detection — see [HIBP integration](integrations/hibp.md).

### MFA enforcement

`MandatoryRoles` is currently a global switch, **not** per-role scoped despite its name: setting
it to any non-empty list makes MFA mandatory for **every** credential, not just ones holding the
listed roles — `Crestacle.Bedrock.Core` has no concept of roles at all (that's a Sentinel/RBAC
concern in a separate package it doesn't depend on), so there is no way to check which roles the
credential being evaluated actually holds.

```csharp
// Makes MFA mandatory for every user, regardless of role — the role names here are
// currently only used to decide WHETHER to turn this on, not WHO it applies to.
opts.Mfa.MandatoryRoles = ["admin", "finance"];
```

Every credential gets a grace period (default: 14 days) to enrol before access is blocked.

---

## Token types and their purpose

Bedrock issues several token types with different lifetimes and scopes. Understanding them helps you configure appropriate expiry windows.

| Token type | Claim | Lifetime | Purpose |
|---|---|---|---|
| Access token | `token_type: "access"` | 15 min (default) | Authorises regular API requests |
| Refresh token | _(opaque, DB-backed)_ | 7 days (default) | Exchanges for new access/refresh pair |
| Challenge token | `token_type: "challenge"` | 5 min | Carries context during MFA at login |
| Enrollment token | `token_type: "enrollment"` | 15 min | Allows access to MFA setup endpoints only |
| Step-up token | `token_type: "step_up"` | 5 min | Single-use; required for sensitive operations |

The scope middleware rejects enrollment tokens on regular endpoints and regular tokens on enrollment endpoints. Step-up tokens are consumed on first use.

---

## Audit trail

All authentication events are recorded in the `AuditEntry` table. Query them via the admin audit endpoint:

```http
GET /api/bedrock/audit?eventType=LoginFailed&from=2025-01-01&to=2025-02-01
Authorization: Bearer <admin-token>
```

Retain audit logs in accordance with your compliance requirements. Consider exporting them to a SIEM via a custom `IBedrockEventPublisher`.

---

## Sensitive operations and step-up authentication

Operations like disabling MFA and viewing recovery codes require step-up authentication — the user must re-prove possession of their second factor even though they already hold a valid access token. This prevents an attacker who steals a session from making security-critical changes.

Endpoints marked with `[RequiresStepUp]` require an `X-Step-Up-Token` header containing a valid, unused step-up JWT. The token is single-use and expires in 5 minutes.

```
1. POST /api/bedrock/step-up/initiate  →  { challengeId, method }
2. POST /api/bedrock/step-up/verify    →  { stepUpToken }
3. POST /api/bedrock/2fa/disable
   X-Step-Up-Token: <stepUpToken>
```
