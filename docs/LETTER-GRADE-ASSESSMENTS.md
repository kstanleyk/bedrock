# Letter-Grade Assessment Process

A standing methodology for grading this codebase's production-readiness, following the same
process used on the sibling `crestacle-smpp` repository
(`docs/LETTER-GRADE-ASSESSMENTS.md` there) — distinct from any point-in-time review of a single
change, this is a repeatable grading cycle for the codebase as a whole.

## Scope: six areas, then the whole codebase

The codebase is assessed in six areas, individually, then as a whole:

1. **Core Library** — `src/Crestacle.Bedrock.Core/`
2. **AspNetCore Layer** — `src/Crestacle.Bedrock.AspNetCore/`
3. **Persistence & Extensions** — `src/Crestacle.Bedrock.EntityFramework/`,
   `src/Crestacle.Bedrock.Redis/`, `src/Crestacle.Bedrock.HaveIBeenPwned/`,
   `src/Crestacle.Bedrock.HardwareTokenSeedImport/`
4. **Sentinel RBAC Suite** — `src/Crestacle.Sentinel.Core/`, `src/Crestacle.Sentinel.AspNetCore/`,
   `src/Crestacle.Sentinel.EntityFramework/`, `src/Crestacle.Bedrock.Sentinel/` (the bridge package)
5. **Test Suite** — `tests/Crestacle.Bedrock.Tests.Unit/`, `tests/Crestacle.Bedrock.Tests.Integration/`,
   `tests/Crestacle.Bedrock.Sentinel.Tests/`, `tests/Crestacle.Sentinel.Tests/`
6. **Architecture/Governance** — `README.md`, `docs/`, `samples/`, `Directory.Build.props`,
   `Directory.Packages.props`, `Bedrock.slnx`

Then **the whole codebase** as a seventh pass — not a re-run of the six areas combined, but a
cross-cutting review freed from each area's siloed scoping, aimed at integration points and
anything a single-area reviewer would never see (does a value set in one package actually flow
correctly into another; does the test suite actually exercise the seams *between* packages, not
just each package in isolation; does a security decision made in one layer get honored by the
next layer downstream).

This two-level cycle (six areas, then the whole codebase) is meant to repeat periodically as the
codebase evolves — each run gets its own dated entry in [History](#history) below.

## Methodology, per area (and for the whole-codebase pass)

1. **Initial review.** A fresh, independent reviewer with no prior context grades the area
   (A+ through F) and lists findings, most severe first. Each reviewer builds and tests their
   own slice themselves rather than trusting any prior report, and reports exact commands and
   output as evidence.
2. **Fix.** Apply each finding. When a finding turns out to be a deliberate design decision on
   inspection, document the rationale instead of reversing the decision — a legitimate outcome,
   not a skipped fix.
3. **Re-audit.** A *fresh* reviewer — no knowledge of the prior round, told only the scope and
   what was just fixed — re-derives the grade from the live repo state.
4. **Repeat** fix → re-audit until **two consecutive rounds** return zero findings (or only
   findings a reviewer explicitly judges don't rise to a real defect).
5. **Verify** every round with a full clean rebuild (0 warnings/0 errors,
   `TreatWarningsAsErrors=true`) and the relevant test slice.
6. **Commit and push** once an area reaches two consecutive clean passes, with a commit message
   that explains *why* each fix was needed, not just what changed.

## History

### Run 1 — 2026-11-24 (single grading pass — no fix cycle)

Seven fresh reviewers, each with no prior context, each told not to trust any other reviewer's
output, graded the live repo once and reported findings. **No fixes were applied in this run —
every finding below is open as of this date.** Each reviewer ran the build and relevant test
command(s) themselves rather than trusting a prior report.

| Area | Grade | Headline findings |
|---|---|---|
| Core Library | B- | `BedrockOptions.Validate()` is dead code despite its doc claiming automatic startup invocation (a missing JWT signing key won't fail fast); 9 of 13 declared domain events — including `AccountLockedEvent` — are never published anywhere, so an event-bus consumer wired to react to a real lockout never fires |
| AspNetCore Layer | **C+ — contains a CRITICAL finding** | MFA-challenge and step-up JWTs are signed with the same key/issuer as real access tokens and are only excluded from the `Default` authorization policy and `BedrockScopeMiddleware` by checking for `token_type == "enrollment"` — `"challenge"`/`"step_up"` are never excluded. A captured 5-minute MFA/step-up token can be replayed as a normal bearer token against any `[Authorize(Policy=Default)]` endpoint, **fully bypassing MFA**, including minting a durable API key or registering a passkey — a persistent backdoor credential, verified empirically. Also: Argon2id hashes don't encode their own cost parameters (a future hardening would silently mass-lock-out every user); logout/session-revoke never blacklists the still-valid access token; mandatory-MFA role scoping is documented but not implemented (all-or-nothing); a timing side-channel reveals which accounts are locked out; passkey login skips the lockout check entirely |
| Persistence & Extensions | C+ | `MemoryBedrockCache`'s single-node distributed-lock is registered `AddScoped`, so every request gets a fresh lock object — the documented NX-gate guarantee never actually holds under concurrent load; `Crestacle.Bedrock.Redis` can't build from a clean checkout (NU1902, missing a `FrameworkReference` workaround present in a sibling package); Postgres optimistic concurrency on `UserCredential`/`Session` is a silent no-op (already tracked as an open P0 in the repo's own roadmap); HaveIBeenPwned's README references method/class names that don't exist in the real code |
| Sentinel RBAC Suite | C+ | Global/shared roles and permissions (the library's own documented seeding pattern) silently grant **zero** permissions the moment any tenant context is active — fails closed, but breaks the exact deployment mode `Crestacle.Bedrock.Sentinel` exists to support, untested by its 82 passing tests; `SentinelClaimsEnricher` looks up the Sentinel user by the wrong key (internal id vs. identity id), permanently nulling name/role claims, masked by a test that bakes in the same wrong assumption; `Crestacle.Bedrock.Sentinel` fails to build (NU1902); `docs/integrations/sentinel.md` is wrong in nearly every code sample |
| Test Suite | **D** | Two of four test projects (`Crestacle.Bedrock.Tests.Unit`, `Crestacle.Bedrock.Sentinel.Tests`) cannot even build (same NU1902 block). The suite that does build and run has **13 deterministic failures** across login, refresh, passkey auth, external login, magic link, and invitation acceptance — traced to a June 2026 cookie-migration commit that never updated the tests, silently red for 5+ months, through a dedicated October quality audit that didn't catch it, with no CI anywhere in the repo to surface it |
| Architecture/Governance | C- | Multiple **backwards security claims**: HIBP documented as fail-closed when the code is deliberately fail-open; the audit endpoint documented as admin-only when it's actually self-service for any authenticated user; the JWT signing-key requirement stated backwards. Copy-paste code samples across README, multi-tenancy, external-IdP, Sentinel, and Redis docs don't compile against the real interfaces. Version number stale by two releases; a false .NET 8 multi-targeting claim (repo is net10.0-only) |
| **Whole codebase** (cross-cutting) | C+ | The solution does not build or test from a clean checkout — 4 of 17 projects fail restore on the same NU1902 chain, including the *one* test project built specifically to validate the Bedrock↔Sentinel bridge, meaning that seam has effectively never had a passing CI run in a reproducible environment. The documented `POST auth/refresh` body contract (`RefreshRequest.RefreshToken`) is dead code — the controller only ever reads the httpOnly cookie, silently breaking refresh for any non-browser client (mobile apps, server-to-server consumers — exactly the kind of client a "Standalone auth microservice" deployment is for). Accounts for most of the Test Suite's 13 failures |

All seven reviewers independently confirmed: no silent exception swallow was found resolving to
an *allowed* authorization outcome; `[MustHavePermission]`/`PermissionAuthorizationHandler` is a
correctly deny-by-default implementation; HaveIBeenPwned's k-anonymity check never transmits a
full password or hash; and the architectural skeleton (package layering, `Bedrock.slnx`,
controller/repository counts, schema/middleware ordering) is accurately documented where checked.

### Overall assessment

**Overall grade: C-.**

This is not an average of the seven numbers above — it's a holistic read, the same way the
whole-codebase pass itself isn't just "combine the other six." Two things cap it hard regardless
of how well any individual slice scored:

1. **A live, concretely-exploitable authorization bypass** (AspNetCore Layer finding #1) that
   lets an attacker skip MFA entirely and plant a durable backdoor credential. For an
   authentication/authorization library, a verified bypass of the second factor is close to the
   worst possible class of finding, and it was found in code already published as
   `Crestacle.Bedrock.AspNetCore` 1.6.2 and consumed by at least one real production application.
2. **The test suite — the thing meant to catch exactly this kind of regression — has been
   silently red on core auth paths for over five months**, with two of its four projects unable
   to even build. A safety net with a 5-month blind spot on login/refresh/passkey/external-login
   is not a safety net.

Layered on top: pervasive documentation inaccuracy including three independently-confirmed
*backwards* security claims (not just stale facts, but guidance that says the opposite of what
the code does), a build that doesn't succeed from a clean checkout at all, and several more
real-but-less-severe correctness bugs (dead domain events, a broken single-node cache lock, a
non-functional multi-tenant RBAC bootstrap path, Postgres optimistic concurrency silently doing
nothing). None of this suggests a broadly incompetent codebase — several reviewers independently
called out genuinely strong engineering in specific areas (constant-time comparisons, correct
k-anonymity, deny-by-default authorization, disciplined rotation/reuse-detection on refresh
tokens, an unusually rigorous self-critical internal roadmap doc that had already found and
tracked some of these issues before this review) — but a production-readiness grade for a
security-critical library has to weight a live auth-bypass and a long-blind test suite above
everything else, which is what keeps this at C- rather than the B-/B+ range the individual-area
scores might otherwise average to.
