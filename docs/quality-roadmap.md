# Quality roadmap — path to A+

**Status: P0 fully closed; P1/P2 mostly closed (2026-11-25).** Logged 2026-10-04 from a full-codebase review (Core, AspNetCore, EntityFramework, plugins, tests, docs). Original assessed grade: **B-** overall. This document is the defect register and the phased plan to close the gap to **A+**.

## Closed

Closed by two independent efforts since this document was filed: a parallel "letter-grade
production-readiness assessment" session (commits through `8a07ca9`), and
`docs/pentest-hardening-plan.md`'s own slices H1–H13 plus its completion-prompt fix (`6e4f6ea`).
See each item's own entry below for the specific commit and verification. Per this document's own
discipline, closed items are kept here (marked `[x]`) rather than deleted, so the defect history
stays auditable.

- **P0 (D1–D5): all five closed.** Four by the parallel session (D1, D2, D3/D4 jointly via the
  optimistic-concurrency token approach, D5), with one important correction surfaced by
  `docs/pentest-hardening-plan.md`'s own completion-prompt dynamic smoke pass:
  `RefreshTokenRepository`/`StepUpChallengeRepository`'s `UpdateAsync` still re-attached entities
  incorrectly, making D3/D4's actual repository-layer behavior 100%-broken on Postgres despite the
  DB-level mechanism being correct and the existing `PostgresConcurrencyTests.cs` passing (it never
  exercised the real repository path). Fixed in `6e4f6ea`, with a new
  `PostgresRepositoryUpdateTests.cs` specifically covering what `PostgresConcurrencyTests.cs` missed.
- **P1 (D6, D11, D13–D15): four of seven closed.** D6 by the parallel session (`cc0b748`); D11,
  D13, D14, D15 by `docs/pentest-hardening-plan.md`'s slices H9, H11, H7, H8 respectively.
  D7, D8, D9, D12 remain open — internal-quality items, not pentest-visible, deliberately left for
  later (see `docs/pentest-hardening-plan.md`'s P3).
- **P2/test-debt (D16–D20): all five closed.** D16 by the parallel session (`0d3b2a8` — and its
  severity was worse than originally filed here, see D16's own entry below); D17–D20 by
  `docs/pentest-hardening-plan.md`'s slice H13 (`5c4d3af`) and H12 (`a25a7f1` for D20's docs half).

---

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

- [x] **D1. Role claims never authorize.** `JwtService.cs:58` emits roles under claim type `"roles"` (plural, JSON array — deliberate, per the comment, to fix frontend deserialization). `BedrockJwtHelper.cs:51` still set `RoleClaimType = ClaimTypes.Role`. No claim was ever emitted under `ClaimTypes.Role`, so `User.IsInRole()` and `[Authorize(Roles = "...")]` silently never matched for any Bedrock-issued token. **Confirmed live bug, not theoretical.** Fixed: `RoleClaimType = "roles"`, matching the real emitted claim key. Regression test deliberately validates against the modern `JsonWebTokenHandler`-equivalent settings (`MapInboundClaims = false`), not the legacy handler's default `true`, which would have silently masked this exact bug by auto-renaming the claim before `RoleClaimType` is even consulted.
- [x] **D2. Passkey login ignores the configurable cookie policy.** Fixed: `BedrockPasskeyController.CompleteAuthentication` now reads `_options.Session.RefreshCookieSameSite` via the same `ToAspNetSameSite` mapping `BedrockAuthController.SetRefreshCookie` uses, instead of hardcoding `SameSite = SameSiteMode.Strict`. Verified with `PasskeyControllerTests.CompleteAuthentication_RefreshCookie_HonorsConfiguredSameSitePolicy`, which fails against the prior hardcoded value (observed `samesite=strict` instead of the default `samesite=none`) and passes against the fix.
- [x] **D3. Refresh-token rotation has no concurrency guard.** Fixed: `RefreshToken` now has a `RowVersion` optimistic-concurrency token (SQL Server `rowversion` / Postgres `xmin`, same multi-provider mechanism D5 added for `UserCredential`/`Session`). `BedrockUnitOfWork.SaveChangesAsync` already translated `DbUpdateConcurrencyException` into `BedrockConcurrencyException` (409) for every save, so no change was needed in `RefreshTokenService.RefreshAsync` itself -- the losing concurrent rotation now fails cleanly with 409 instead of silently succeeding. Verified against a real PostgreSQL instance: `PostgresConcurrencyTests.RefreshToken_ConcurrentRotations_SecondSaveThrowsConcurrencyException` fails (no exception, both rotations silently succeed) without the `RowVersion` column and passes with it.
- [x] **D4. Step-up token consumption is TOCTOU-racy.** Fixed: `StepUpChallenge` now has the same multi-provider `RowVersion`/xmin optimistic-concurrency token as `RefreshToken` (D3). `RequiresStepUpAttribute.OnAuthorizationAsync` catches `BedrockConcurrencyException` around the save and surfaces it as the same "Step-up token has already been used" 403 the explicit `UsedAt`-check already returns for the sequential-reuse case, so a genuine race loses the same way a replay does, without a different-shaped 409 and without misclassifying a benign race. Verified against a real PostgreSQL instance: `PostgresConcurrencyTests.StepUpChallenge_ConcurrentMarkUsed_SecondSaveThrowsConcurrencyException` fails (no exception, both uses silently succeed) without the `RowVersion` column and passes with it.
- [x] **D5. No Postgres concurrency-token path for Bedrock's own entities.** `UserCredentialConfiguration` / `SessionConfiguration` hardcode `IsRowVersion()` (SQL Server `rowversion`). Sentinel's equivalent helper, `ModelBuilderExtensions.UseSentinelPostgreSqlConcurrency` (`xmin`), turned out to have zero actual callers anywhere in this solution — an opt-in method nobody ever opted into, exactly the kind of footgun this fix avoids repeating for Bedrock. Fixed: `BedrockContext.OnModelCreating` auto-detects the Npgsql provider (`Database.ProviderName`) and maps the real PostgreSQL `xmin` system column as the concurrency token for `UserCredential`/`Session`, ignoring the SQL-Server-only `RowVersion` byte[] column in that case — no second method call required. Verified against a real local PostgreSQL instance (not just read/reasoned about): two independent `DbContext`s updating the same row, second `SaveChangesAsync` now throws `DbUpdateConcurrencyException` as expected; confirmed via negative control that it silently succeeded (no exception, second write clobbers the first) before this fix. New tests: `PostgresConcurrencyTests.cs`. Also fixed in passing: `PostgresSchemaTests.cs`'s raw SQL hardcoded the wrong schema name (`'bedrock'`/`"Bedrock"`) instead of the real `auth` schema `BedrockContext` actually configures — these tests, gated behind `[PostgresFact]` and skipped without a live connection, had evidently never been run against a real Postgres instance before.

### P1 — Structural defects & inconsistencies

- [x] **D6. Duplicate, contradictory domain events.** Fixed (`cc0b748`): `Events/DomainEvents.cs` deleted entirely; the one type it had that was actually constructed anywhere (`AccountUnlockedEvent`, plus `AccountLockedEvent`) moved into `DomainEvents/CredentialEvents.cs`, the namespace actually in live use. The other 8 declared-but-dead types removed. `AccountLockedEvent` is now actually published at both real lockout-transition moments, verified by a negative control (temporarily removing the publish call reproduces "the collection is empty").
- [ ] **D7. Exception taxonomy diverges between libraries.** Bedrock has a systematic `BedrockException` base + `BedrockErrorCodes` with HTTP-status/`Retry-After` semantics per type. Sentinel's `SentinelConcurrencyException` / `SentinelNotFoundException` inherit directly from `Exception` with no common base and no error-code concept — callers can't catch Sentinel failures generically the way they can Bedrock's.
- [ ] **D8. Encapsulation inconsistently applied.** `UserRole.cs` / `RolePermission.cs` use fully public `{ get; set; }` with no factory or invariants, unlike every sibling aggregate (`User`, `Role`, `Permission`, `PendingAssignment`, `AuditEntry`), which all use private setters + `Create()`.
- [ ] **D9. Repository/UnitOfWork discipline differs by library.** Bedrock repositories defer `SaveChanges` to `BedrockUnitOfWork`; Sentinel repositories (`RoleRepository.cs:131`, `UserRepository.cs:124`, `PendingAssignmentRepository.cs:107`) call `context.SaveChangesAsync` directly with no UoW at all. No explicit `BeginTransactionAsync` exists anywhere for multi-repository business operations, so cross-aggregate atomicity is unverifiable.
- [x] **D10. `ArchitectureTests.cs` only covers Sentinel.** Fixed (`5c4d3af`, slice H13): a new `tests/Crestacle.Bedrock.Tests.Unit/ArchitectureTests.cs` adds the same `Core ← EntityFramework ← AspNetCore` layering checks for the Bedrock assembly stack.
- [x] **D11. `AdminLock()` uses a magic sentinel instead of explicit state.** Fixed (`2a652fa`, `docs/pentest-hardening-plan.md` slice H9): `UserCredential` gained an explicit `IsAdminLocked` flag (the 100-year `LockoutEnd` sentinel is kept for existing `IsLockedOut()` callers, as defense in depth); `BedrockAccountLockedException` now builds a generic "locked by an administrator" message for the admin-locked case instead of interpolating the raw sentinel date, while the genuine timed-lockout message is unchanged. Two new tests cover both branches.
- [ ] **D12. Doc/implementation mismatch.** `SentinelClaimsEnricher.cs:21-22` states that `PermissionAuthorizationHandler` "resolves permissions from the database (with caching)." `PermissionAuthorizationHandler.cs:21` calls the repository directly — no cache is visible at that layer. Either the comment is wrong or the cache is undocumented.

### P2 — Defensive-engineering gaps

- [x] **D13. Sync-over-async in the HIBP validator.** Fixed (`69be799`, `docs/pentest-hardening-plan.md` slice H11): `IPasswordValidator` converted end-to-end to async (`IsValidAsync`), removing the `Task.Run(...).GetAwaiter().GetResult()` bridge entirely. All three implementers and both callers updated to the new signature — not just documented as a bounded risk, actually removed.
- [x] **D14. No catch-all exception handler.** Fixed (`8ff14f7`, slice H7): `BedrockExceptionMiddleware` now has a final `catch (Exception ex)` after all `BedrockException` catches, returning a structured 500 with a correlation ID (`TraceIdentifier`) and no leaked message/stack trace. The awkward `when (ex is BedrockException bex)` simplified to `catch (BedrockException bex)`. All three samples now register `UseExceptionHandler` for non-Development environments.
- [x] **D15. No input validation on request DTOs.** Fixed (`93998be` + `5778254`, slice H8): `[Required]`/`[EmailAddress]`/`[StringLength]` added to all 28 records in `Models/Requests.cs` and the 4 Sentinel inline request records. One record (`AssignRoleRequest`) genuinely has no annotatable constraint (bare `Guid`/nullable `DateTime`) — documented rather than forced.
- [x] **D16. Wasteful cache registration — and worse than "harmless": a real correctness bug.**
  `MemoryBedrockCache` was registered `AddScoped` while wrapping an already-singleton
  `IMemoryCache`; `MemoryPermissionCache` was already `AddSingleton` (this item's original
  text was wrong about that half). Beyond the wasted per-request allocation, `MemoryBedrockCache
  .TryAcquireLockAsync` locks on an instance field (`_lockGate`) — with `AddScoped`, every
  request got its OWN `_lockGate`, so the `lock` statement never actually serialized two
  concurrent callers against each other, silently defeating the documented single-node NX-gate
  guarantee (`MaxConcurrentSessions` enforcement, JTI-blacklist atomicity) even within one
  process. Fixed: `AddSingleton<IBedrockCache, MemoryBedrockCache>()`.

### P3 — Test & documentation debt

- [x] **D17. Refresh-token *chain* reuse detection is untested.** Fixed (`5c4d3af`, slice H13): `HardeningTests.RefreshReuseDetection_ReplayingStaleToken_RevokesLiveTipToo` rotates twice, replays the now-stale root token, and confirms the live tip (issued by the second rotation, not involved in the replay) is also rejected afterward.
- [x] **D18. Cookie/SameSite resolution is untested.** Fixed (`5c4d3af`, slice H13): a `[Theory]` over `Strict`/`Lax` × 2 realms (4 combinations) confirms `Set-Cookie` uses each realm's own cookie name/expiry while honoring the server-wide `SameSite` setting.
- [x] **D19. Fingerprint-truncation fix is untested.** Fixed (`5c4d3af`, slice H13): a 300-char `User-Agent` test confirms login still returns 200 and the persisted fingerprint is truncated to exactly 128 characters.
- [x] **D20. Docs have drifted behind shipped features.** Fixed (`a25a7f1`, slice H12, plus the parallel session's `8a07ca9` for the change-password path specifically): `docs/api-reference.md` now documents all 6 Sentinel RBAC controllers, the admin `reset-password` endpoint, `SessionOptions.RefreshCookieSameSite`, and rotation-chain-revocation behavior; `docs/configuration-reference.md` updated with the `SameSite` option.

---

## Phased plan to A+

### Phase Q1 — Stop the bleeding (targets: all P0 items) — ✅ complete
- [x] Fix D1: switched `RoleClaimType` to `"roles"`, matching the real emitted claim key.
- [x] Fix D2: `BedrockPasskeyController` now routes through `RefreshCookieSameSitePolicy`.
- [x] Fix D3: `RefreshToken` gained a `RowVersion`/`xmin` optimistic-concurrency token (not a cache lock as originally proposed) — the losing concurrent rotation now 409s. **Note:** the repository-layer re-attach bug that made this 100%-broken on Postgres (not just under contention) was caught and fixed separately by `docs/pentest-hardening-plan.md`'s completion-prompt dynamic smoke pass (`6e4f6ea`) — see that document's own writeup.
- [x] Fix D4: same `RowVersion`/`xmin` approach as D3 (not the originally-proposed conditional `UPDATE`) — `RequiresStepUpAttribute` catches the concurrency exception and maps it to the existing 403. Same repository-layer bug and fix as D3's note above.
- [x] Fix D5: ported the `xmin` approach to `BedrockContext.OnModelCreating` (auto-detected by provider, not an opt-in second method call) for `UserCredential` / `Session` on Postgres hosts.
- [x] Each fix above ships with a regression test in the same PR — `PostgresConcurrencyTests.cs` plus, after the dynamic-smoke-pass finding, `PostgresRepositoryUpdateTests.cs`.

### Phase Q2 — Close the security-critical test gap (targets: D17–D19, plus regression tests for Q1) — ✅ complete
- [x] Added a test proving replay of a stale refresh token revokes the *entire* chain including the live tip.
- [x] Added tests covering `ResolveRefreshCookieSettings` across realms and both `SameSite` values.
- [x] Added an oversized-`User-Agent` test asserting truncation, not a DB exception.
- [x] Extended `ArchitectureTests.cs` (D10) to cover the Bedrock assembly stack.
- [ ] Gate: no PR touching `RefreshTokenService`, cookie resolution, or fingerprinting merges without a test exercising the changed behavior — process item, not yet formally enforced (e.g. via CI).

### Phase Q3 — Structural consistency (targets: D6–D9, D11, D12) — partially complete
- [x] D6: deleted the dead domain-event set, kept the one actually wired to a publisher.
- [ ] Give Sentinel a `SentinelException` base + error-code enum mirroring `BedrockException`/`BedrockErrorCodes` (D7).
- [ ] Bring `UserRole`/`RolePermission` in line with the rest of the domain model — private setters, `Create()` factories (D8).
- [ ] Decide on one data-access discipline — either every repository goes through a UnitOfWork, or document why Sentinel's direct-`SaveChanges` approach is intentional — and add an explicit transaction boundary for any operation spanning more than one aggregate (D9).
- [x] D11: explicit `IsAdminLocked` flag; exception message no longer leaks the raw sentinel date for the admin-locked case.
- [ ] Fix or correct the `SentinelClaimsEnricher` caching comment to match actual behavior (D12) — investigated and found to be a false positive (caching does exist one layer below); no code change needed, but the comment itself hasn't been explicitly re-worded yet.

### Phase Q4 — Defensive hardening (targets: D13–D16) — ✅ complete
- [x] Made `HaveIBeenPwnedPasswordValidator` fully async end-to-end via a new async `IPasswordValidator` interface — not just documented as a bounded bridge, actually removed.
- [x] Added a catch-all `catch (Exception)` → structured 500 fallback in `BedrockExceptionMiddleware`, logged with correlation ID; simplified the `when (ex is BedrockException)` clause.
- [x] Added `[Required]`/`[EmailAddress]`/length validation attributes to `Models/Requests.cs` and the 4 Sentinel inline records.
- [x] Changed `MemoryBedrockCache` registration from `AddScoped` to `AddSingleton` (`MemoryPermissionCache` was already `AddSingleton`).

### Phase Q5 — Documentation currency + process (targets: D20, and keeping the above from regressing) — mostly complete
- [x] Updated `docs/security.md`-adjacent docs (`docs/api-reference.md`, `docs/configuration-reference.md`) with rotation-chain revocation behavior and the cookie `SameSite` option.
- [ ] Add a short "what changed and why" note to each docs page whenever a security-relevant behavior ships — process item, not yet formally adopted.
- [x] Re-ran this document's checklist; moved closed items into the "Closed" section above rather than deleting them, so the defect history stays auditable.

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
