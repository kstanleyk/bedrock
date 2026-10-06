# Crestacle.Sentinel.Controls — Design Source

**Status:** Design locked — 2026-10-06 (§7 open questions resolved in §7a; planning only, no code yet)
**Purpose:** Single source of truth for extracting the dual-control (step-up / maker-checker /
four-eyes / break-glass) engine, currently bespoke in `omni-api`
(`omni-api/docs/features/unit-roles-and-controls/design.md`), into a shared Bedrock package so
every Bedrock/Sentinel-based project gets it without reimplementing it. Companion migration plan:
`omni-api/docs/features/migrate-to-sentinel-controls/design.md`. Consuming roadmap:
`bursary-api/docs/CONTROL_POLICY_ROADMAP.md`.

> Sections marked **(open)** are not yet decided — see §7. Nothing here is built until a slice's
> build prompt (`prompt.md`) references it.

---

## 1. Problem

`omni-api` built a generic-in-spirit dual-control engine (registry → gate → maker-checker/co-sign/
step-up mechanisms → break-glass) entirely inside its own `Omni.Application`/`Omni.Domain` layers.
It is well-designed — one engine serving many operations, not per-feature bespoke flows — but it
is not reusable as written: two of its core types are coupled to omni's own domain model.

`bursary-api` already has exactly one hardcoded instance of the same underlying problem (four-eyes
on voucher approve, baked into the `Voucher` aggregate, not table-driven) and no path at all for
step-up, maker-checker, escalation thresholds, or an emergency-override when no approver is
reachable. Any third Bedrock-based project will hit the same gap again.

Both `omni-api` and `bursary-api` already consume `Crestacle.Bedrock.*`/`Crestacle.Sentinel.*` from
this repo via a local NuGet feed — the reuse mechanism already exists. The dual-control engine does
not live here yet.

## 2. Solution

Extract the generic ~80% of omni's engine into a new package, `Crestacle.Sentinel.Controls`,
following this repo's existing split-by-ASP.NET-Core-dependency convention (`.Core` / `.EntityFramework`
/ `.AspNetCore`, matching `Crestacle.Sentinel.*` and `Crestacle.Bedrock.*`). The ~20% that is
genuinely project-specific — the actual registry rows, and what "checker authority" means in a
given host's role model — stays in each consuming project, same as every other Bedrock/Sentinel
extension point (compare: Sentinel ships `[MustHavePermission]` and the permission model; it does
not ship any given project's `AppFeature` enum).

Two generalizations are required before extraction — copying omni's types verbatim would ship a
library coupled to one host:

1. **`UnitPosition` does not move.** Omni's `ControlledOperation.CheckerMinPosition` is typed as
   `UnitPosition` (Head/Assistant/Staff) directly. That is omni's domain, not a universal concept —
   bursary has flat roles (Bursar/StationSupervisor/FddAccountant), no three-tier position axis. The
   library instead defines an opaque `IAuthorityRequirement` marker and a host-implemented
   `IAuthorityResolver` port. Omni implements it by wrapping its existing position check; bursary
   implements it by wrapping a permission-holding check.
2. **`FacilityId`/`ServiceUnitId` do not move as two fixed fields.** Omni's threshold-override
   resolution is two hardcoded columns. Bursary's natural scope today is just `StationId`, and may
   grow into an N-level `OrgUnit` hierarchy (see bursary's own planning notes — not yet a public
   design doc as of this writing). The library instead defines `IScopePathProvider`: given an
   operation's scope id, return an ordered list of override-lookup scope ids, most-specific first.
   Threshold/mechanism resolution walks that list, falling back to the registry default at the end.
   Today both hosts return a one-element path; neither host needs to change when the other's
   hierarchy depth changes later.

Everything else — the decision types, the generic maker-checker engine, the co-sign bridge, the
step-up adapter (already Bedrock-only), and break-glass — moves close to verbatim.

## 3. What moves vs. what stays (precise)

| Moves into the library | Stays per-project |
|---|---|
| `ControlMechanism`, `ControlRequest`, `ControlDecision` (+ subtypes), `CoSignOutcome`, `MakerCheckerDecision`/`Routing`/`ActionResult` — pure data shapes | **The registry** — the actual list of operation keys, features, mechanisms, thresholds. Domain data, not engine code. |
| `ControlledOperation` record, generalized: `CheckerAuthority: IAuthorityRequirement` instead of `UnitPosition` | **`IAuthorityRequirement` implementations** — e.g. omni's `PositionRequirement(UnitPosition Min)`, bursary's `PermissionRequirement(string Feature)` |
| `IControlGate`/`ControlGate` (internals call the two new ports instead of a host context directly) | **`IAuthorityResolver` implementation** — "does this user meet requirement X at this scope" |
| `IControlThresholdResolver`/default impl, generalized to walk a scope path | **`IScopePathProvider` implementation** — the override-lookup chain for a scope |
| `PendingApproval` aggregate + EF config, `IPendingApprovalRepository`, `MakerCheckerGate`/`IMakerCheckerGate`, `IApprovableOperation` seam — already subject-agnostic | **`IApprovableOperation` implementations** — the real apply logic per controlled operation |
| `IStepUpContext` + a Bedrock-backed default impl — already Bedrock-only | Admin screen controller routes/permission wiring (DTO shapes shared, endpoints aren't) |
| `ICoSignContext` interface + a default impl (both current hosts validate a second Bedrock bearer token the same way — verify this holds before shipping a default, §7 open item) | Each host's existing `ICurrentUserService`/`IUnitOfWork`/`IAuditLogService` — unchanged |
| `ControlledOpThreshold` aggregate, scope key generalized | |
| `BreakGlassEvent` + review workflow — generalized: `Scope` becomes a free-text string, not omni's `BreakGlassScope` enum | |
| `[RequiresControl("<key>")]` ASP.NET Core action filter (mirrors `RequiresStepUpAttribute`) | |
| DI wiring extensions (`AddSentinelControls`, `AddSentinelControlsEntityFramework`, `AddSentinelControlsAspNetCore`) | |

## 4. Package shape

Follows the existing `Crestacle.Sentinel.*` split:

- **`Crestacle.Sentinel.Controls`** — decision types, `IControlGate`/`ControlGate`, the two new
  ports (`IAuthorityRequirement`, `IAuthorityResolver`, `IScopePathProvider`), `PendingApproval`,
  `ControlledOpThreshold`, `BreakGlassEvent` (as plain aggregates using `Crestacle.Sentinel.Core`'s
  existing `Entity<TId>` — no new base type, no host SharedKernel dependency), `MakerCheckerGate`,
  `IApprovableOperation`. Depends on `Crestacle.Sentinel.Core` only.
- **`Crestacle.Sentinel.Controls.EntityFramework`** — EF configurations/migration snippets for the
  three aggregates, default repository implementations, `AddSentinelControlsEntityFramework(...)`.
  Depends on `Crestacle.Sentinel.Controls` + `Crestacle.Sentinel.EntityFramework`.
- **`Crestacle.Sentinel.Controls.AspNetCore`** — `[RequiresControl]` filter, a Bedrock-backed
  `IStepUpContext` default implementation (wraps `Crestacle.Bedrock.AspNetCore`'s existing
  `StepUpService`), the co-sign bridge default implementation, admin policy DTOs,
  `AddSentinelControlsAspNetCore(...)`. Depends on `Crestacle.Sentinel.Controls` +
  `Crestacle.Sentinel.AspNetCore` + `Crestacle.Bedrock.AspNetCore`.

## 5. Locked decisions

1. `UnitPosition` and the two-field scope do not move verbatim — see §2.
2. `BreakGlassEvent.Scope` becomes `string` in the library (free-text operation-adjacent key), not
   an enum — enums tied to one host's feature set don't belong in a shared type.
3. The registry itself (`ControlledOperationsRegistry` as a static table) is explicitly **not**
   part of the library — every host writes its own, same as every host writes its own `AppFeature`
   enum today.
4. `PendingApproval`/`ControlledOpThreshold`/`BreakGlassEvent` use `Crestacle.Sentinel.Core`'s
   existing `Entity<TId>` base type, not a new one and not any host's own SharedKernel — this keeps
   the library's aggregates independent of which SharedKernel a given host happens to use.
5. No behavioural change to omni intended by this extraction alone — the omni migration
   (`omni-api/docs/features/migrate-to-sentinel-controls/`) is a separate, later effort that swaps
   omni onto the extracted library without changing what any of its 8 already-wired operations do.

## 6. Implementation shape (for later — no code now)

See `roadmap.md` for the slice sequence and `prompt.md` for the execution/validation prompts.

## 7. Open questions / parking lot

1. **Default `ICoSignContext` implementation** — both omni and bursary validate a second Bedrock
   bearer token today; confirm this is genuinely identical before shipping one default rather than
   leaving it host-implemented like `IAuthorityResolver`/`IScopePathProvider`.
2. **Escalation-threshold shape** — omni's `EscalationThreshold` (bump to a facility-wide approver
   above a second, higher amount) is a second `IAuthorityRequirement`-and-amount pair. Confirm the
   generalized shape handles this without a special case.
3. **`PendingApproval.PayloadJson`** — omni serializes with `System.Text.Json` against the CLR type
   at submit time and deserializes nowhere generic (the `IApprovableOperation` implementation reads
   it back typed). Confirm the library doesn't need to know the payload's shape at all — it should
   not, but verify no slice assumes otherwise.
4. **Versioning** — this repo ships one shared `VersionPrefix` (currently 1.6.0) across all
   packages. Confirm whether adding `Crestacle.Sentinel.Controls` is a minor bump (1.7.0) for the
   whole repo, consistent with how prior package additions were versioned.
5. **Admin policy DTO ownership** — `GetControlledOperations`/`SetControlledOpThreshold` shapes are
   listed as library code in §3, but the actual registry they reflect is host-owned. Confirm the
   DTO can be fully generic (operation key + current effective values) without needing to know the
   host's registry type.

## 7a. Resolutions (2026-10-06, design-lock slice E0)

1. **Default `ICoSignContext` impl — ship one, in `Crestacle.Sentinel.Controls.AspNetCore`.**
   Checked both hosts' actual wiring, not just their design docs: `omni-api`'s
   `Omni.Infrastructure/DependencyInjection.cs` and `bursary-api`'s
   `Bursary.Infrastructure/DependencyInjection.cs` both only set `opts.Jwt.SigningKey` on a shared
   `Crestacle.Bedrock` options object — neither host reimplements token issuance/validation itself.
   They are not "similar," they are *the same validator*, by construction. The one place this isn't
   yet exploited is omni's own `SentinelCoSignContext`, which hand-rolls a second
   `TokenValidationParameters` block instead of reusing Bedrock's own validation service — a
   pre-existing omni wart the extraction should fix, not copy. Resolution: ship a default backed by
   whatever Bedrock's own token-validation service is (not a hand-rolled `JwtSecurityTokenHandler`
   call), reading the second bearer from an `X-CoSign-Token` header, enforcing co-signer ≠ actor,
   then delegating the authority/witness checks to `IAuthorityResolver` (never an inline position
   lookup — that was only in omni's version because the port didn't exist yet). Bursary's eventual
   `PermissionRequirement` plugs into the exact same default with zero duplication.

2. **Escalation-threshold shape — a symmetric second pair, no special case.** `EscalationAuthority:
   IAuthorityRequirement?` alongside `EscalationThreshold: decimal?` on `ControlledOperation`
   mirrors `CheckerAuthority`/`Threshold` exactly; `IControlThresholdResolver` grows one more
   effective-value method (`EffectiveEscalationThreshold`/`EffectiveEscalationAuthority`) using the
   same scope-path walk. No new concept, no branching logic the primary pair doesn't already have.
   (Already reflected in E2's execution prompt below — this resolution just makes it official.)

3. **`PendingApproval.PayloadJson` stays fully opaque — confirmed, not assumed.** Read
   `MakerCheckerGate.RouteAsync` directly: it serializes with
   `JsonSerializer.Serialize(payload, payload.GetType())` and never deserializes it anywhere in the
   gate/engine. The only reader is each host's own `IApprovableOperation.ApplyAsync`, which knows its
   own payload's CLR type by construction (it's keyed by `OperationKey`, which the host also owns).
   The library needs zero knowledge of payload shape, now or later.

4. **Versioning — minor bump, but flagged as convention, not repo precedent.** `Directory.Build.props`
   history shows no clean prior case of "new package family → minor bump": the jump from 1.4.7 to
   1.6.0 rode along with a feature commit (configurable refresh-cookie/reuse-detection), not a
   package addition, and Sentinel itself was added at repo init rather than as a later bump. There is
   no tag/changelog to anchor a stronger claim. Decision: bump `VersionPrefix` to **1.7.0** anyway —
   three new public packages is new surface area, not a patch, under ordinary semver regardless of
   this repo's own history — but treat this as the first time the convention is actually exercised,
   not as "this is already how we do it."

5. **Admin policy DTO — fully generic, confirmed by design, not just hoped.** The shape needed is
   effective values only: `(OperationKey, Feature, EffectiveMechanism, EffectiveThreshold,
   EffectiveEscalationThreshold, HasScopeOverride)`. Critically, the DTO does **not** need to expose
   `CheckerAuthority`/`EscalationAuthority` at all to stay useful for an admin screen's first cut —
   sidestepping the harder problem of describing an opaque `IAuthorityRequirement` generically. A
   host that wants to show *which* authority is required renders that itself (it owns the concrete
   requirement types); the library's contribution is only the mechanism/threshold/override-presence
   facts, which are genuinely host-agnostic. (Already reflected in E7's execution prompt below.)
