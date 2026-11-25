# API reference

All endpoints are prefixed with the configured base path. The default is `api/bedrock`, so a route shown as `auth/login` is reachable at `POST /api/bedrock/auth/login`.

The base path is set when registering controllers:

```csharp
.AddBedrockControllers("api/v1/auth")  // custom prefix
```

All responses use the `BedrockResponse<T>` envelope:

```json
{
  "success": true,
  "code": "OK",
  "errors": [],
  "data": { ... }
}
```

On failure, `success` is `false`, `code` describes the error category, and `errors` contains human-readable messages.

---

## Authentication

### Register

```
POST auth/register
```

Creates a new user account. Sends a verification email.

**Request**
```json
{ "email": "user@example.com", "password": "..." }
```

---

### Confirm email

```
POST auth/confirm-email
```

Verifies the email address using the token from the verification email.

**Request**
```json
{ "token": "..." }
```

---

### Resend confirmation

```
POST auth/resend-confirmation
```

Re-sends the verification email.

**Request**
```json
{ "email": "user@example.com" }
```

---

### Login

```
POST auth/login
```

Authenticates with email and password. Returns tokens directly if MFA is not required.

**Request**
```json
{
  "email": "user@example.com",
  "password": "...",
  "fingerprintHash": "optional-device-fingerprint"
}
```

**Response (no MFA)**
```json
{
  "accessToken": "eyJ...",
  "refreshToken": "...",
  "accessTokenExpiresAt": "2025-01-01T00:15:00Z",
  "requiresMfa": false
}
```

**Response (MFA required)**
```json
{
  "requiresMfa": true,
  "challengeToken": "eyJ...",
  "challengeMethod": "Totp",
  "challengeExpiresAt": "2025-01-01T00:05:00Z"
}
```

**Response (MFA enrollment required)**
```json
{
  "requiresEnrollment": true,
  "enrollmentToken": "eyJ...",
  "mfaGracePeriodEndsAt": "2025-01-15T00:00:00Z"
}
```

---

### Verify MFA

```
POST auth/verify-2fa
```

Completes login after an MFA challenge.

**Request**
```json
{
  "challengeToken": "eyJ...",
  "code": "123456",
  "fingerprintHash": "optional"
}
```

**Response** — same token pair as a successful login.

---

### Refresh token

```
POST auth/refresh
```

Exchanges a refresh token for a new access/refresh token pair. The old refresh token is revoked.

**Request**
```json
{ "refreshToken": "...", "fingerprintHash": "optional" }
```

The refresh token is normally delivered and read back via an `HttpOnly`, `Secure` cookie
(`Login`/`Refresh`/`Verify2FA`/passkey-login all set it; `Refresh`/`Revoke` both read it from
`Request.Cookies` first, falling back to `refreshToken` in the JSON body if the cookie is absent).
The cookie's name and `Path` come from `SessionOptions.RefreshCookieName` /
`SessionOptions.RefreshCookiePath` (realm-scoped — resolved per request from the `Host` header via
`IBedrockRealmProvider`, falling back to the base options when the host doesn't match a configured
realm); its `SameSite` attribute comes from `SessionOptions.RefreshCookieSameSite`
(`Strict`/`Lax`/`None`, default `None`) and is **not** realm-scoped — one value applies to every
realm in a given deployment. See `docs/configuration-reference.md`'s `SessionOptions` entry for the
full default rationale.

**Reuse detection and rotation-chain revocation.** Each successful refresh revokes the presented
token and issues a new one (`RefreshToken.ReplacedByTokenHash` links old → new). If a refresh token
that was already rotated once is presented again — `RevokedAt` set AND `ReplacedByTokenHash`
populated — this is treated as token theft: `RefreshTokenService` walks the rotation chain forward
from that token via each successor's own `ReplacedByTokenHash` and revokes every still-active token
(and its session) it finds, **including the live tip of the chain that the legitimate holder is
still using**. The request itself still fails with the normal "invalid or expired" error, but the
side effect is that the legitimate session is forced to re-authenticate on its next refresh —
revoking only the replayed token would leave the attacker able to retry it harmlessly forever
without ever actually compromising the live session, which is why the whole chain is revoked instead.

---

### Revoke token

```
POST auth/revoke
```

Revokes a refresh token, ending the session.

**Request**
```json
{ "refreshToken": "..." }
```

---

### Forgot password

```
POST auth/forgot-password
```

Sends a password reset email. Always returns success to prevent user enumeration.

**Request**
```json
{ "email": "user@example.com" }
```

---

### Reset password

```
POST auth/reset-password
```

Sets a new password using the token from the reset email.

**Request**
```json
{ "token": "...", "newPassword": "..." }
```

---

### Magic link request

```
POST auth/magic-link
```

Sends a magic link (passwordless login email).

**Request**
```json
{ "email": "user@example.com" }
```

---

### Magic link verify

```
POST auth/magic-link/verify
```

Authenticates using the token from a magic link. May return MFA challenge or enrollment requirement.

**Request**
```json
{ "tokenHash": "...", "fingerprintHash": "optional" }
```

---

### External login

```
POST auth/external-login
```

Authenticates using a token from an OAuth/OIDC provider. Creates a new account if none exists for the external identity.

**Request**
```json
{ "provider": "google", "providerToken": "..." }
```

---

### Accept invitation

```
POST auth/accept-invitation
```

Accepts an admin-created invitation, sets a password, and logs in.

**Request**
```json
{ "tokenHash": "...", "password": "..." }
```

---

### Request enrollment token

```
POST auth/request-enrollment
Authorization: Bearer <access-token>
```

Issues an enrollment token for beginning MFA setup. Requires an authenticated session.

---

### Confirm email change

```
POST auth/confirm-email-change
```

Confirms an email address change using the token from the change-confirmation email.

**Request**
```json
{ "tokenHash": "..." }
```

---

## Account

All account endpoints require `Authorization: Bearer <access-token>`.

### Delete account

```
DELETE account/
```

Permanently deletes the authenticated user's account.

---

### Change password

```
POST auth/change-password
```

**Request**
```json
{ "currentPassword": "...", "newPassword": "..." }
```

---

### Request email change

```
POST account/request-email-change
```

Sends a confirmation email to the new address.

**Request**
```json
{ "newEmail": "new@example.com" }
```

---

### Record consent

```
POST account/consent
```

Records a consent decision (e.g. accepting terms of service).

**Request**
```json
{ "policyType": "TermsOfService", "policyVersion": "2025-01" }
```

---

### Get consent records

```
GET account/consent
```

Returns the user's consent history.

---

### Link external identity

```
POST account/link-external
```

Links an OAuth/OIDC identity to the current account.

**Request**
```json
{ "provider": "github", "providerToken": "..." }
```

---

### Unlink external identity

```
DELETE account/external/{provider}
```

Removes a linked external identity.

---

### List external identities

```
GET account/external
```

Returns all linked external identities.

---

## MFA

### Set up TOTP

```
POST 2fa/setup-totp
Authorization: Bearer <enrollment-token>
```

Returns a QR code URI for scanning with an authenticator app.

**Response**
```json
{ "qrUri": "otpauth://totp/..." }
```

---

### Confirm TOTP

```
POST 2fa/confirm-totp
Authorization: Bearer <enrollment-token>
```

Confirms TOTP setup by verifying the first code. Returns recovery codes.

**Request**
```json
{ "code": "123456" }
```

**Response**
```json
{ "codes": ["AAAA-BBBB", "CCCC-DDDD", ...] }
```

---

### Set up OTP (email/SMS)

```
POST 2fa/setup-otp
Authorization: Bearer <enrollment-token>
```

Enrols email or SMS OTP as the MFA method.

**Request**
```json
{ "method": "EmailOtp" }
```

---

### Get recovery code count

```
GET 2fa/recovery-codes
Authorization: Bearer <access-token>
X-Step-Up-Token: <step-up-token>
```

Returns the number of unused recovery codes remaining.

---

### Regenerate recovery codes

```
POST 2fa/recovery-codes/regenerate
Authorization: Bearer <access-token>
X-Step-Up-Token: <step-up-token>
```

Invalidates all existing recovery codes and issues a new set.

---

### Disable MFA

```
POST 2fa/disable
Authorization: Bearer <access-token>
X-Step-Up-Token: <step-up-token>
```

Disables MFA for the authenticated user. Requires a step-up token.

---

## Step-up authentication

Used before sensitive operations (disabling MFA, viewing recovery codes).

### Initiate step-up

```
POST step-up/initiate
Authorization: Bearer <access-token>
```

**Response**
```json
{ "challengeId": "...", "method": "Totp" }
```

---

### Verify step-up

```
POST step-up/verify
Authorization: Bearer <access-token>
```

**Request**
```json
{ "challengeId": "...", "code": "123456" }
```

**Response**
```json
{ "stepUpToken": "eyJ..." }
```

Pass the step-up token in the `X-Step-Up-Token` header on the target endpoint.

---

## Passkeys (WebAuthn/FIDO2)

### Begin passkey registration

```
POST passkeys/register/begin
Authorization: Bearer <access-token>
```

Returns WebAuthn creation options for the browser.

---

### Complete passkey registration

```
POST passkeys/register/complete
Authorization: Bearer <access-token>
```

**Request**
```json
{ "attestationResponse": { ... }, "friendlyName": "My YubiKey" }
```

---

### List passkeys

```
GET passkeys
Authorization: Bearer <access-token>
```

---

### Delete passkey

```
DELETE passkeys/{id}
Authorization: Bearer <access-token>
```

---

### Begin passkey authentication

```
POST passkeys/authenticate/begin
```

**Request**
```json
{ "email": "user@example.com" }
```

Returns WebAuthn get options for the browser.

---

### Complete passkey authentication

```
POST passkeys/authenticate/complete
```

**Request**
```json
{ "assertionResponse": { ... } }
```

Returns the same token response as a successful login.

---

## API keys

All API key endpoints require `Authorization: Bearer <access-token>`.

### Create API key

```
POST account/api-keys/
```

**Request**
```json
{ "name": "CI pipeline" }
```

**Response** — includes the raw key value (only shown once):
```json
{
  "id": "...",
  "rawKey": "bdrk_...",
  "prefix": "bdrk_",
  "name": "CI pipeline",
  "createdAt": "...",
  "expiresAt": null
}
```

---

### List API keys

```
GET account/api-keys/
```

---

### Delete API key

```
DELETE account/api-keys/{keyId}
```

---

## Sessions

All session endpoints require `Authorization: Bearer <access-token>`.

### List sessions

```
GET sessions
```

Returns all active sessions for the authenticated user.

---

### Revoke session

```
DELETE sessions/{sessionId}
```

---

### Revoke all sessions

```
DELETE sessions
```

Revokes all sessions for the authenticated user, including the current one.

---

## Audit (admin)

```
GET audit
Authorization: Bearer <access-token>
```

Requires the `BedrockAdmin` policy -- the `bedrock_admin` claim must be present in the access
token (provided by `IBedrockClaimsEnricher`). Not self-service: a regular authenticated user
cannot query another user's (or their own) audit trail through this endpoint.

Query parameters: `userId`, `eventType`, `from` (ISO 8601), `to` (ISO 8601), `page` (default 1), `pageSize` (default 50, max 200).

---

## Admin

All admin endpoints require the `BedrockAdmin` policy. The `bedrock_admin` claim must be present in the access token (provided by `IBedrockClaimsEnricher`).

### List users

```
GET admin/users?page=1&pageSize=50
```

### Get user

```
GET admin/users/{userId}
```

### Lock account

```
POST admin/users/{userId}/lock
```

### Unlock account

```
POST admin/users/{userId}/unlock
```

### Reset MFA

```
POST admin/users/{userId}/reset-mfa
```

### Expire password

```
POST admin/users/{userId}/expire-password
```

Forces the user to change their password on next login.

### Revoke all sessions

```
DELETE admin/users/{userId}/sessions
```

### Reset password (admin)

```
POST admin/users/{userId}/reset-password
```

**Request**
```json
{ "newPassword": "..." }
```

Directly sets a new password for the user, bypassing the self-service email-reset flow — for
admin-initiated resets (e.g. account-recovery support requests). Validates the new password against
the configured password policy and reuse history exactly like self-service reset. Also clears any
active lockout (the common reason an admin reset is requested in the first place) and revokes all
of the user's existing sessions/refresh tokens, forcing re-authentication with the new password.

### Change email

```
POST admin/users/{userId}/change-email
```

**Request**
```json
{ "newEmail": "real.person@example.com" }
```

Directly sets a new email address, bypassing the self-service confirmation-link flow — for
deployments with no working email delivery. Revokes all active sessions. No-op if
`newEmail` matches the account's current address.

### Anonymise account

```
DELETE admin/users/{userId}/anonymize
```

Permanently removes PII from the account (GDPR right to erasure).

### Create invitation

```
POST admin/invitations
```

**Request**
```json
{ "targetEmail": "newuser@example.com", "roleHint": "editor" }
```

---

## RBAC administration (Sentinel)

Sentinel's six management controllers are mounted at a **hardcoded** `api/auth` prefix —
unlike every endpoint above, they do **not** honour the configurable Bedrock base path
(`.AddBedrockControllers("...")`); routes below are shown exactly as reachable.

Every endpoint requires `[MustHavePermission(feature, action)]` (built-in features:
`SentinelFeature.User`, `.Role`, `.Audit`; actions: `AppAction.Create/Read/Update/Delete`) except
`GET api/auth/permissions/me`, which only requires an authenticated user (`[Authorize]`) since it
returns the caller's own permissions.

### List users

```
GET api/auth/users?page=1&pageSize=50&search=
```

Requires `User.Read`.

### Get user

```
GET api/auth/users/{id}
```

Requires `User.Read`.

### Assign role to user

```
POST api/auth/users/{id}/roles
```

Requires `User.Update`.

**Request**
```json
{ "roleId": "...", "expiresOn": "optional, ISO-8601" }
```

Returns `200 OK` for an immediate assignment, or `202 Accepted` with
`{ "pendingAssignmentId": "..." }` when the target role has `RequiresDualApproval = true` (4-eyes
principle) — a second admin must approve via `POST api/auth/pending-assignments/{id}/approve`
before the assignment takes effect. An actor can neither modify their own role assignments nor
assign a role carrying a permission they do not themselves hold (privilege-escalation guards).

### Remove role from user

```
DELETE api/auth/users/{id}/roles/{roleId}
```

Requires `User.Update`. Same self-modification guard as assignment.

### List roles

```
GET api/auth/roles?page=1&pageSize=50&search=
```

Requires `Role.Read`.

### Get role

```
GET api/auth/roles/{id}
```

Requires `Role.Read`.

### Assign permission to role

```
POST api/auth/roles/{id}/permissions
```

Requires `Role.Update`.

**Request**
```json
{ "permissionId": "feature.action" }
```

`Internal`-type roles are immutable via this endpoint (`403`). Rejects with `409 Conflict` if the
permission conflicts with one the role already has (Separation of Duties — see Conflicts below).
An actor may only grant a permission they themselves hold.

### Remove permission from role

```
DELETE api/auth/roles/{id}/permissions/{permissionId}
```

Requires `Role.Update`. Same `Internal`-role guard as assignment.

### Get my permissions

```
GET api/auth/permissions/me
```

Requires only an authenticated caller (no specific permission). Returns the full permission-ID set
held by the current user, resolved the same way `PermissionAuthorizationHandler` resolves it.

### List pending (dual-approval) assignments

```
GET api/auth/pending-assignments?page=1&pageSize=50
```

Requires `User.Read`.

### Approve pending assignment

```
POST api/auth/pending-assignments/{id}/approve
```

Requires `User.Update`. Returns `409 Conflict` if already reviewed, expired, or the approver is the
same user who submitted the request.

### Reject pending assignment

```
POST api/auth/pending-assignments/{id}/reject
```

Requires `User.Update`.

**Request**
```json
{ "reason": "optional, free text" }
```

Same `409 Conflict` conditions as approval.

### List Separation-of-Duties conflicts

```
GET api/auth/conflicts
```

Requires `Role.Read`.

### Add conflict pair

```
POST api/auth/conflicts
```

Requires `Role.Update`.

**Request**
```json
{ "permissionIdA": "feature.action", "permissionIdB": "feature.action" }
```

A conflict pair prevents both permissions from ever being assigned to the same role simultaneously.

### Remove conflict pair

```
DELETE api/auth/conflicts/{id}
```

Requires `Role.Update`.

### Sentinel audit log

```
GET api/auth/audit?actorIdentityId=&action=&from=&to=&page=1&pageSize=50
```

Requires `Audit.Read`. All query parameters are optional and combinable; `action` is one of
`RoleAssigned`, `RoleRemoved`, `PermissionAssigned`, `PermissionRemoved`. This is Sentinel's own
RBAC-change audit trail (`AuditEntry`/`AuditRepository`) — a **distinct** log from Bedrock's own
authentication audit documented above under "Audit (admin)"; the two are unrelated subsystems with
independent authorization and, in a multi-tenant deployment, independent tenant scoping. Results
are filtered to the caller's own tenant whenever `ITenantContext.TenantId` resolves to a non-null
value; a `null` tenant context means single-tenant mode and returns rows across all tenants by
design — see `docs/multi-tenancy.md`'s "null-TenantId contract" note.

---

## JWKS discovery

```
GET /.well-known/jwks.json
```

Returns the public JSON Web Key Set used to verify Bedrock-issued JWTs. This endpoint is always at the root path regardless of the configured base path. Returns an empty `keys` array when HS256 (symmetric) signing is used, since the signing key cannot be public.
