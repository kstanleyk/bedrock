# Quality roadmap — path to A+

**Status: NOT STARTED.** Logged 2026-10-04 from a full-codebase review (Core, AspNetCore, EntityFramework, plugins, tests, docs). Current assessed grade: **B-** overall. This document is the defect register and the phased plan to close the gap to **A+**.

Grading at the time of review:

| Layer | Grade |
|---|---|
| Core domain (`Bedrock.Core` / `Sentinel.Core`) | B+ |
| ASP.NET Core / auth integration | B- |
| EntityFramework / caching / plugins | B+ |
| Tests & engineering hygiene | B- |

---

## Defect register

Each item below is filed under the phase that fixes it. File:line references are accurate as of commit `c7a6364` (2026-10-04) — re-verify before starting work, line numbers drift.

### P0 — Correctness & security regressions (ship-blocking)

- [ ] **D1. Role claims never authorize.** `JwtService.cs:58` emits roles under claim type `"roles"` (plural, JSON array — deliberate, per the comment, to fix frontend deserialization). `BedrockJwtHelper.cs:51` still sets `RoleClaimType = ClaimTypes.Role`. No claim is ever emitted under `ClaimTypes.Role`, so `User.IsInRole()` and `[Authorize(Roles = "...")]` silently never match for any Bedrock-issued token. **Confirmed live bug, not theoretical.**
- [ ] **D2. Passkey login ignores the configurable cookie policy.** `BedrockPasskeyController.cs:134` hardcodes `SameSite = SameSiteMode.Strict`. `BedrockAuthController.SetRefreshCookie` (`BedrockAuthController.cs:431`) reads the configurable `RefreshCookieSameSitePolicy` instead. Passkey-based session restore breaks in exactly the cross-site scenario commit `ace63d1` was meant to fix for password login.
- [ ] **D3. Refresh-token rotation has no concurrency guard.** `RefreshTokenService.RefreshAsync` has no locking or optimistic-concurrency check (unlike `IssueAsync`, which uses a cache lock). Two concurrent requests presenting the same valid refresh token can both pass the `IsActive` check and both rotate before either write lands — double-issuing tokens and defeating single-use rotation semantics.
- [ ] **D4. Step-up token consumption is TOCTOU-racy.** `RequiresStepUpAttribute.OnAuthorizationAsync` (`RequiresStepUpAttribute.cs:50-60`) does read → check `UsedAt is not null` → `MarkUsed` → save with no transaction or concurrency token. Two parallel requests with the same step-up JWT can both pass the used-check before either save commits.
- [ ] **D5. No Postgres concurrency-token path for Bedrock's own entities.** `UserCredentialConfiguration` / `SessionConfiguration` hardcode `IsRowVersion()` (SQL Server `rowversion`). Sentinel already solved the Postgres equivalent via `ModelBuilderExtensions.UseSentinelPostgreSqlConcurrency` (`xmin`), but that fix was never ported to Bedrock's own `CredentialRepository.cs` / `SessionRepository.cs`, despite comments there anticipating exactly this problem.

### P1 — Structural defects & inconsistencies

- [ ] **D6. Duplicate, contradictory domain events.** `Events/DomainEvents.cs` and `DomainEvents/CredentialEvents.cs` both define `EmailVerifiedEvent`, `PasswordChangedEvent`, `MfaEnabledEvent`, `MfaDisabledEvent`, `MfaChallengeSucceededEvent`, `AnomalyDetectedEvent`, `StepUpCompletedEvent`, `LoginSucceededEvent` with **different field order/shape** in each namespace (e.g. `AnomalyDetectedEvent`'s `IpAddress`/`FingerprintHash` positions are swapped between the two). Positional-record footgun; looks like an unfinished migration.
- [ ] **D7. Exception taxonomy diverges between libraries.** Bedrock has a systematic `BedrockException` base + `BedrockErrorCodes` with HTTP-status/`Retry-After` semantics per type. Sentinel's `SentinelConcurrencyException` / `SentinelNotFoundException` inherit directly from `Exception` with no common base and no error-code concept — callers can't catch Sentinel failures generically the way they can Bedrock's.
- [ ] **D8. Encapsulation inconsistently applied.** `UserRole.cs` / `RolePermission.cs` use fully public `{ get; set; }` with no factory or invariants, unlike every sibling aggregate (`User`, `Role`, `Permission`, `PendingAssignment`, `AuditEntry`), which all use private setters + `Create()`.
- [ ] **D9. Repository/UnitOfWork discipline differs by library.** Bedrock repositories defer `SaveChanges` to `BedrockUnitOfWork`; Sentinel repositories (`RoleRepository.cs:131`, `UserRepository.cs:124`, `PendingAssignmentRepository.cs:107`) call `context.SaveChangesAsync` directly with no UoW at all. No explicit `BeginTransactionAsync` exists anywhere for multi-repository business operations, so cross-aggregate atomicity is unverifiable.
- [ ] **D10. `ArchitectureTests.cs` only covers Sentinel.** The three layering tests enforce `Core ← EntityFramework ← AspNetCore` for the Sentinel assemblies only. Bedrock's larger, more security-sensitive stack (`Bedrock.Core` / `EntityFramework` / `AspNetCore` / `Redis` / `HaveIBeenPwned`) has no equivalent enforcement.
- [ ] **D11. `AdminLock()` uses a magic sentinel instead of explicit state.** `UserCredential.AdminLock()` (`UserCredential.cs:217-222`) sets a 100-year `LockoutEnd` rather than a distinct status flag. `BedrockAccountLockedException` then interpolates that raw date into a user-facing message, risking a "locked until [100 years from now]" string reaching an end user.
- [ ] **D12. Doc/implementation mismatch.** `SentinelClaimsEnricher.cs:21-22` states that `PermissionAuthorizationHandler` "resolves permissions from the database (with caching)." `PermissionAuthorizationHandler.cs:21` calls the repository directly — no cache is visible at that layer. Either the comment is wrong or the cache is undocumented.

### P2 — Defensive-engineering gaps

- [ ] **D13. Sync-over-async in the HIBP validator.** `HaveIBeenPwnedPasswordValidator.cs:34` implements the sync `IsValid` via `Task.Run(() => IsBreachedAsync(...)).GetAwaiter().GetResult()`, burning a thread-pool thread per registration for up to the 3-second timeout under load.
- [ ] **D14. No catch-all exception handler.** `BedrockExceptionMiddleware.InvokeAsync` only catches the `BedrockException` family. Any other unhandled exception — such as the DB-level overflow fixed ad hoc in `c7a6364` — still propagates as a raw, unformatted 500. A generic `catch (Exception)` fallback would catch this entire class of bug centrally instead of per call-site. (The existing `catch (Exception ex) when (ex is BedrockException bex)` on line 63 is also just an awkward spelling of `catch (BedrockException bex)` — simplify while touching this.)
- [ ] **D15. No input validation on request DTOs.** `Models/Requests.cs` has zero `[Required]` / `[EmailAddress]` / length constraints across roughly 25 request records (`RegisterRequest`, `LoginRequest`, etc.). Malformed bodies pass model binding and only fail deep in service logic, producing inconsistent 400 responses.
- [ ] **D16. Wasteful cache registration.** `MemoryBedrockCache` / `MemoryPermissionCache` are registered `AddScoped` while wrapping an already-singleton `IMemoryCache` — harmless but allocates per request for no reason.

### P3 — Test & documentation debt

- [ ] **D17. Refresh-token *chain* reuse detection is untested.** Existing tests (`RefreshTokenServiceTests.cs`, `HardeningTests.cs:107`) only assert that a *stale* token is rejected. None asserts that replaying a stale token also revokes the *live* tip of the rotation chain — the actual novel behavior added in `24a8eb7`. A regression that reverted chain-walking to single-token revocation would pass every current test.
- [ ] **D18. Cookie/SameSite resolution is untested.** No test exercises `ResolveRefreshCookieSettings`, per-realm cookie name/expiry, or the `RefreshCookieSameSitePolicy` option added in `ace63d1`.
- [ ] **D19. Fingerprint-truncation fix is untested.** No test sends an oversized `User-Agent` to verify the truncation added in `c7a6364` against the 128-char `device_fingerprint` column.
- [ ] **D20. Docs have drifted behind shipped features.** `docs/security.md` and `docs/configuration-reference.md` have zero mentions of rotation-chain revocation or cookie `SameSite` policy, despite both being live, security-relevant behavior.

---

## Phased plan to A+

### Phase Q1 — Stop the bleeding (targets: all P0 items)
- [ ] Fix D1: either switch `RoleClaimType` to `"roles"` with a custom claim-type mapping, or emit an additional singular `ClaimTypes.Role` claim per role — pick one source of truth and delete the other.
- [ ] Fix D2: route `BedrockPasskeyController` through the same `RefreshCookieSameSitePolicy` resolution path as `BedrockAuthController`; delete the hardcoded `Strict`.
- [ ] Fix D3: wrap `RefreshTokenService.RefreshAsync` in the same cache-lock pattern already used by `IssueAsync`, or add an optimistic-concurrency check on the token row.
- [ ] Fix D4: make the read-check-mark-save in `RequiresStepUpAttribute` atomic — a single conditional `UPDATE ... WHERE UsedAt IS NULL` (or a concurrency token) instead of read-then-write.
- [ ] Fix D5: port `UseSentinelPostgreSqlConcurrency`'s `xmin` approach to `UserCredentialConfiguration` / `SessionConfiguration` for Postgres hosts.
- [ ] Each fix above ships with a regression test in the same PR — no exceptions, since the whole point is these were previously untested.

### Phase Q2 — Close the security-critical test gap (targets: D17–D19, plus regression tests for Q1)
- [ ] Add a test proving replay of a stale refresh token revokes the *entire* chain including the live tip (not just rejects the stale one).
- [ ] Add tests covering `ResolveRefreshCookieSettings` across realms and both `SameSite` values.
- [ ] Add an oversized-`User-Agent` test asserting truncation, not a DB exception.
- [ ] Extend `ArchitectureTests.cs` (D10) to cover the Bedrock assembly stack, not just Sentinel.
- [ ] Gate: no PR touching `RefreshTokenService`, cookie resolution, or fingerprinting merges without a test exercising the changed behavior.

### Phase Q3 — Structural consistency (targets: D6–D9, D11, D12)
- [ ] Delete one of the two duplicate domain-event sets (D6); keep whichever is actually wired to a publisher, confirm via usage search before deleting.
- [ ] Give Sentinel a `SentinelException` base + error-code enum mirroring `BedrockException`/`BedrockErrorCodes` (D7).
- [ ] Bring `UserRole`/`RolePermission` in line with the rest of the domain model — private setters, `Create()` factories (D8).
- [ ] Decide on one data-access discipline — either every repository goes through a UnitOfWork, or document why Sentinel's direct-`SaveChanges` approach is intentional — and add an explicit transaction boundary for any operation spanning more than one aggregate (D9).
- [ ] Replace the 100-year-lockout sentinel with an explicit `LockReason`/`IsAdminLocked` flag; fix the exception message to not leak the raw sentinel date (D11).
- [ ] Fix or correct the `SentinelClaimsEnricher` caching comment to match actual behavior (D12).

### Phase Q4 — Defensive hardening (targets: D13–D16)
- [ ] Make `HaveIBeenPwnedPasswordValidator` fully async end-to-end (add an async validator interface, or document the sync entrypoint as a thin intentional bridge with a bounded, documented worst case).
- [ ] Add a catch-all `catch (Exception)` → structured 500 fallback in `BedrockExceptionMiddleware`, logged with correlation ID; simplify the existing `when (ex is BedrockException)` clause to a direct `catch (BedrockException)`.
- [ ] Add `[Required]`/`[EmailAddress]`/length validation attributes to `Models/Requests.cs`, or adopt FluentValidation consistently if attribute validation doesn't cover a case.
- [ ] Change `MemoryBedrockCache`/`MemoryPermissionCache` registration from `AddScoped` to `AddSingleton`.

### Phase Q5 — Documentation currency + process (targets: D20, and keeping the above from regressing)
- [ ] Update `docs/security.md` with rotation-chain revocation behavior and `docs/configuration-reference.md` with the cookie `SameSite` option.
- [ ] Add a short "what changed and why" note to each docs page whenever a security-relevant behavior ships — tie doc updates to the same PR as the code change, not a follow-up.
- [ ] Re-run this document's checklist at each minor version bump; move it to `docs/quality-roadmap.md`'s "Closed" section (see below) as items land, rather than deleting them, so the defect history stays auditable.

---

## Definition of A+

All of the following hold simultaneously:

1. **Zero open P0/P1 items** in the defect register above.
2. **Every security-sensitive behavior change ships with a test that fails without the change** — specifically refresh-token rotation chains, cookie/SameSite resolution, and any future auth-adjacent fix.
3. **One consistent pattern per concern across both libraries** — one exception taxonomy shape, one repository/UoW discipline, one encapsulation style for entities — Bedrock and Sentinel should read as one codebase, not two with a shared solution file.
4. **`ArchitectureTests.cs` enforces layering for both Bedrock and Sentinel assembly stacks.**
5. **Docs are updated in the same PR as the behavior they describe** — `docs/security.md` and `docs/configuration-reference.md` have no missing mentions of shipped, security-relevant options.
6. **No sync-over-async bridges and no read-check-write races remain in security-critical paths.**

When all six hold, re-run the full four-layer review (Core, AspNetCore, EntityFramework, tests/hygiene) — expect each layer to independently land at A/A+ before calling the project done.
