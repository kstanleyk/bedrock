# Crestacle.Sentinel.Controls Roadmap

Design source: `docs/features/sentinel-controls/design.md`
**Status: E0 complete (2026-10-06). E1 may begin.**

## Phase E0 — Design lock (pre-build gate)
- [x] Resolve the §7 open questions needed to start (default co-sign impl, escalation-threshold
      shape, versioning bump) — see design.md §7a
- [x] Build prompts written for E1+ — `prompt.md`

## Phase E1 — Project scaffold
- [ ] `Crestacle.Sentinel.Controls`, `Crestacle.Sentinel.Controls.EntityFramework`,
      `Crestacle.Sentinel.Controls.AspNetCore` projects added to `Bedrock.slnx`
- [ ] Per-package `README.md` stub (matching the existing `Crestacle.Bedrock.AspNetCore/README.md`
      convention); root `README.md` packages table gains three rows

## Phase E2 — Core decision types + the two new ports
- [ ] `ControlMechanism`, `ControlRequest`, `ControlDecision`, `CoSignOutcome` ported as-is
- [ ] `IAuthorityRequirement` (marker) + `IAuthorityResolver` port defined
- [ ] `IScopePathProvider` port defined
- [ ] `ControlledOperation` ported, generalized (`CheckerAuthority: IAuthorityRequirement`)
- [ ] `IControlGate`/`ControlGate` ported, rewired onto the two new ports
- [ ] `IControlThresholdResolver`/default impl ported, generalized to walk a scope path

## Phase E3 — Generic maker-checker engine
- [ ] `PendingApproval` aggregate (on `Crestacle.Sentinel.Core.Entity<TId>`) + EF configuration
- [ ] `IPendingApprovalRepository`, default EF implementation
- [ ] `MakerCheckerGate`/`IMakerCheckerGate`, `IApprovableOperation` seam + dispatch

## Phase E4 — Co-sign and step-up adapters
- [ ] `ICoSignContext` port (+ default impl if §7 Q1 resolves yes)
- [ ] `IStepUpContext` + default impl wrapping `Crestacle.Bedrock.AspNetCore`'s `StepUpService`

## Phase E5 — Threshold override storage
- [ ] `ControlledOpThreshold` aggregate (scope-id generalized), `IControlledOpThresholdRepository`,
      EF configuration/migration snippet

## Phase E6 — Break-glass primitive
- [ ] `BreakGlassEvent` (scope as `string`) + review workflow + repository + EF
      configuration/migration snippet

## Phase E7 — Admin policy contracts + `[RequiresControl]`
- [ ] Generic `GetControlledOperations`/`SetControlledOpThreshold` DTO shapes
- [ ] `[RequiresControl("<key>")]` ASP.NET Core action filter

## Phase E8 — DI wiring + docs + package version
- [ ] `AddSentinelControls`, `AddSentinelControlsEntityFramework`, `AddSentinelControlsAspNetCore`
- [ ] `docs/architecture.md`/`docs/api-reference.md` gain a Controls section
- [ ] `VersionPrefix` bumped per §7 Q4's resolution; `dotnet pack` produces the three new packages
      into `artifacts/`

## Phase E9 — Validation harness
- [ ] A new `samples/` project (mirroring `Embedded`/`Standalone`/`ExternalIdp`) implementing the
      two host ports minimally, exercising all four mechanisms + break-glass end to end
- [ ] `tests/Crestacle.Sentinel.Controls.Tests` — unit coverage for `ControlGate` decision logic,
      `MakerCheckerGate` routing, `PendingApproval`/`BreakGlassEvent` invariants

## Completion
- [ ] All packages build clean, `dotnet pack` succeeds, sample host exercises every mechanism
- [ ] `omni-api/docs/features/migrate-to-sentinel-controls/` and `bursary-api/CONTROL_POLICY_ROADMAP.md`
      may both begin — independently, on their own schedules (2026-10-06 decision: bursary no
      longer waits on omni's migration; see `CONTROL_POLICY_ROADMAP.md`'s own note)
