# Crestacle.Sentinel.Controls — Build Prompts

**Status:** Ready — 2026-10-06 (E0 complete; §7a resolutions locked — E4/E7 below updated to match)
**Design source:** `docs/features/sentinel-controls/design.md`
**Roadmap:** `docs/features/sentinel-controls/roadmap.md`
**Structure:** E0 (design lock) → E1 (scaffold) → E2 (core decision types + ports) → E3 (maker-checker
engine) → E4 (co-sign/step-up) → E5 (threshold storage) → E6 (break-glass) → E7 (admin contracts +
`[RequiresControl]`) → E8 (DI wiring + docs + version) → E9 (validation harness), each as 1+ slice
× (1 build prompt + 1 validation prompt).

Each section has a header (outside the box) and a paste block. Copy everything inside the fenced
block into a fresh Claude session.

**Working directory:** `/Users/kstanleyk/Developer/libs/bedrock`

**Sequencing rule:** No slice may begin until the prior slice's validation returns "All pass."
**E2 must land before E3–E7** (everything else consults the gate/ports it defines).

**Source reference for extraction:** the pre-extraction implementation lives in
`/Users/kstanleyk/Developer/omni/omni-api/src/Omni.Application/Administration/Controls/` and
`/Users/kstanleyk/Developer/omni/omni-api/src/Omni.Domain/Administration/Aggregates/` (`PendingApproval`,
`ControlledOpThreshold`) and `/Users/kstanleyk/Developer/omni/omni-api/src/Omni.Domain/Emergency/Aggregates/BreakGlassEvent.cs`.
Read the referenced file before porting it — these prompts describe what changes, not the full
original shape.

**Build/commit convention:** `dotnet build` at the solution level (`Bedrock.slnx`) must stay clean
(`TreatWarningsAsErrors` is already on repo-wide). Follow this repo's existing conventional-commit
style (`feat(sentinel-controls-eX.Y): ...`); push to `dev`.

---

## SLICE E0 — Design lock — ✅ complete (2026-10-06)

Resolutions recorded in design.md §7a. Kept below for the record; do not re-run.

### EXECUTION PROMPT E0

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read docs/features/sentinel-controls/design.md in full before anything else.

Goal: resolve the design's §7 open questions so E1+ can proceed without stalling mid-slice. This is
a documentation-only slice — no code.

1. §7 Q1 (default ICoSignContext impl): read the co-sign validation logic in omni-api's
   ICoSignContext usage (ControlGate.EvaluateFourEyesAsync) and bursary-api's JWT validation
   pipeline (SECURITY.md §1). Confirm whether both hosts validate a second bearer token identically
   enough to ship one default implementation in Crestacle.Sentinel.Controls.AspNetCore, or whether
   this must stay a host-implemented port like IAuthorityResolver. Record the decision + reasoning
   in design.md §7, replacing "(open)" with the resolution.
2. §7 Q2 (escalation threshold shape): confirm the generalized IAuthorityRequirement design handles
   omni's EscalationThreshold (a second IAuthorityRequirement + amount pair) without a special case
   in ControlledOperation or ControlDecision.ApprovalRequired. Record the resolved shape.
3. §7 Q3 (PendingApproval.PayloadJson): confirm no slice needs the library to interpret the payload
   shape — it should stay fully opaque end to end. Record confirmation.
4. §7 Q4 (versioning): decide the VersionPrefix bump for this repo once the three new packages ship
   (read Directory.Build.props's current value first). Record the decision.
5. §7 Q5 (admin DTO ownership): confirm GetControlledOperations/SetControlledOpThreshold DTOs can be
   fully generic (operation key + effective values only, no reference to any host's registry type).
   Record confirmation.

Update design.md directly: replace each resolved "(open)" question with its answer, under a new
"## 7a. Resolutions" section (keep §7 itself as the historical list of what was asked).

No build step (no code changed). Commit:
git add -A
git commit -m "docs(sentinel-controls-e0): resolve design-lock open questions"
git push origin dev
```

### VALIDATION PROMPT E0

```
Verify Slice E0. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. design.md §7a exists and resolves all five open questions with stated reasoning, not just a
   yes/no.
2. No source file under src/ was touched in this slice's commit.
3. The E1 scaffold slice below is consistent with whatever §7a decided (e.g. if Q1 resolved "no
   default impl," E4's execution prompt must not ship one — flag a mismatch now rather than at E4).

Decision: All 3 pass -> proceed to E1. Any fail -> fix first.
```

---

## SLICE E1 — Project scaffold

### EXECUTION PROMPT E1

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §4 (package shape). E0 complete.

Goal: three empty, building projects wired into Bedrock.slnx — no Controls logic yet.

1. Create src/Crestacle.Sentinel.Controls/Crestacle.Sentinel.Controls.csproj following the existing
   Crestacle.Sentinel.Core.csproj shape (same <PropertyGroup> conventions: AssemblyName,
   RootNamespace, PackageId, a one-line <Description>). Add a ProjectReference to
   Crestacle.Sentinel.Core.

2. Create src/Crestacle.Sentinel.Controls.EntityFramework/Crestacle.Sentinel.Controls.EntityFramework.csproj,
   following Crestacle.Sentinel.EntityFramework.csproj's shape. ProjectReferences: Crestacle.Sentinel.Controls,
   Crestacle.Sentinel.EntityFramework. PackageReference Microsoft.EntityFrameworkCore (version from
   Directory.Packages.props — do not hardcode a version in this csproj).

3. Create src/Crestacle.Sentinel.Controls.AspNetCore/Crestacle.Sentinel.Controls.AspNetCore.csproj,
   following Crestacle.Sentinel.AspNetCore.csproj's shape. ProjectReferences: Crestacle.Sentinel.Controls,
   Crestacle.Sentinel.AspNetCore, Crestacle.Bedrock.AspNetCore.

4. Add all three <Project Path="..."> entries to Bedrock.slnx under the existing /src/ folder,
   placed after the Crestacle.Bedrock.Sentinel entry (alphabetical-by-introduction order, matching
   the existing list).

5. Each new project gets an empty placeholder class (e.g. a single internal marker file) so the
   build has something to compile — do NOT add real Controls types yet (that's E2+).

6. Add a short README.md to each new project directory, matching the structure of
   src/Crestacle.Bedrock.AspNetCore/README.md (one-paragraph purpose statement; no usage examples
   yet since there's no API surface).

7. Update the root README.md packages table (the one listing Crestacle.Bedrock.Core,
   Crestacle.Sentinel.Core, etc.) with three new rows for the Controls packages, descriptions from
   design.md §4.

Build: dotnet build Bedrock.slnx — zero errors, zero warnings.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e1): scaffold Controls/EntityFramework/AspNetCore projects"
git push origin dev
```

### VALIDATION PROMPT E1

```
Verify Slice E1. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings (TreatWarningsAsErrors is repo-wide).
2. All three new .csproj files exist with correct ProjectReferences (verify by inspecting each
   file, not just that the solution builds — a missing reference might not surface as a build error
   yet since there's no real code using it).
3. Bedrock.slnx lists all three new projects under /src/.
4. Each new project has a README.md; the root README.md packages table has three new rows.
5. No Controls domain/application types exist yet (this slice is scaffold-only) — confirm by
   grepping src/Crestacle.Sentinel.Controls* for anything beyond the placeholder marker file.

Decision: All 5 pass -> proceed to E2. Any fail -> fix first.
```

---

## SLICE E2 — Core decision types + the two new ports

### EXECUTION PROMPT E2

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §2 (the two generalizations), §3 (moves table). E1 complete. Read the source files
listed under "Source reference for extraction" at the top of this document before porting anything.

Goal: the decision types, the two new host ports, and a working IControlGate — ported from omni,
generalized per design.md §2. No maker-checker/co-sign/step-up behavior yet (E3-E4); this slice
ships the catalogue-consult shape only, matching how omni's own R3.1 slice scoped itself.

1. In src/Crestacle.Sentinel.Controls/, port verbatim (namespace Crestacle.Sentinel.Controls):
   - ControlMechanism enum (None, StepUp, MakerChecker, FourEyes)
   - ControlRequest record — keep OperationKey, ServiceUnitId (rename to ScopeId — see step 3),
     Amount, SubjectId, Payload, Escalate
   - ControlDecision abstract record + all five subtypes (Allowed, StepUpRequired, ApprovalRequired,
     CoSignRequired, Denied) — StepUpRequired's Challenge type and ApprovalRequired's authority
     parameter change per steps 2/3 below
   - CoSignOutcome record

2. Define the authority port (replaces UnitPosition coupling):
   - public interface IAuthorityRequirement — empty marker interface. Hosts define their own
     concrete implementations (e.g. omni's eventual PositionRequirement(UnitPosition Min), bursary's
     eventual PermissionRequirement(string Feature)) — do NOT define any concrete implementation in
     this library.
   - public interface IAuthorityResolver { Task<bool> MeetsAsync(IAuthorityRequirement requirement,
     Guid scopeId, CancellationToken ct); } — host-implemented.
   - ControlledOperation record: port omni's shape but CheckerMinPosition becomes
     CheckerAuthority: IAuthorityRequirement. Keep Key, Feature (now a plain string, not AppFeature —
     the library has no AppFeature enum), Control, Threshold, WitnessRequired, EscalationThreshold,
     and add EscalationAuthority: IAuthorityRequirement? (nullable — only set when EscalationThreshold
     is set) per design.md §7a's resolution of Q2.

3. Define the scope-path port (replaces the two-field FacilityId/ServiceUnitId coupling):
   - public interface IScopePathProvider { Task<IReadOnlyList<Guid>> GetOverridePathAsync(string
     operationKey, Guid scopeId, CancellationToken ct); } — ordered most-specific first; the last
     element is the top of whatever hierarchy the host has today (today: one element for both known
     hosts). Host-implemented.
   - Rename ControlRequest.ServiceUnitId to ScopeId throughout (this is the id IScopePathProvider
     resolves a path from, not necessarily a "unit" in every host).

4. Threshold/mechanism resolution:
   - public interface IControlledOpThresholdRepository { Task<ControlledOpThreshold?> GetAsync(Guid
     scopeId, string operationKey, CancellationToken ct); } (the generic form — E5 defines the
     ControlledOpThreshold aggregate and an EF implementation; this interface lives here since
     ControlThresholdResolver depends on it).
   - IControlThresholdResolver: port omni's four methods (EffectiveThreshold/EffectiveEscalation
     Threshold/EffectiveMechanism/EffectiveCheckerAuthority — renamed from EffectiveCheckerMinPosition),
     each now walking IScopePathProvider's returned path (first scope id with a configured override
     wins) before falling back to a host-supplied registry lookup delegate — see step 6.
   - ControlThresholdResolver default impl: for each scope id in the path (in order), check the
     repository; return the first non-null override field found; else the registry default.

5. IControlGate/ControlGate: port omni's EvaluateAsync, with these changes:
   - Takes a registry lookup delegate at construction (Func<string, ControlledOperation?>
     TryGetOperation) instead of a static ControlledOperationsRegistry.TryGet call — the library has
     no registry of its own (design.md §5 decision 3). Inject this via DI as a delegate the host
     registers (see E8).
   - Replace HoldsFeature(op.Feature)'s AppFeature-specific prefix check with a host-agnostic
     Func<string, bool> permissionCheck delegate the caller supplies via a second constructor
     parameter, OR take an IAuthorityRequirement representing "holds the feature" and resolve it via
     IAuthorityResolver — prefer the latter if it does not force every host to express RBAC-feature-
     holding as an IAuthorityRequirement awkwardly; otherwise keep a small dedicated
     IFeatureAuthorizationCheck port. Pick whichever keeps ControlGate's constructor to 4-5
     dependencies and document the choice in a doc comment (this is a genuine design call omni did
     not have to make — it hardcoded AppFeature).
   - Replace CallerMeetsPositionAsync with a call to IAuthorityResolver.MeetsAsync(op.CheckerAuthority
     or op.EscalationAuthority, request.ScopeId, ct).
   - Co-sign and step-up branches stay structurally the same but reference ICoSignContext/
     IStepUpContext interfaces only (no implementation yet — E4).

6. Registration shape: do not wire DI yet (E8). For this slice, write ControlGate so it can be
   constructed directly in a unit test with fake delegates/ports — that is the slice's actual proof
   of "the coupling is gone."

Build: dotnet build Bedrock.slnx — zero errors, zero warnings.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e2): decision types + IAuthorityResolver/IScopePathProvider + ControlGate"
git push origin dev
```

### VALIDATION PROMPT E2

```
Verify Slice E2. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings.
2. grep the entire src/Crestacle.Sentinel.Controls* tree for "UnitPosition", "FacilityId", and
   "ServiceUnitId" (as a field name, not a local rename artifact) — zero hits. This is the concrete
   proof the two couplings from design.md §2 are actually gone, not just renamed.
3. IAuthorityRequirement is an empty marker interface with NO concrete implementation anywhere in
   this library (concrete implementations are host-only, per design.md §5 decision 3's spirit
   extended to this type).
4. ControlGate has no reference to any static registry — it takes a lookup delegate/function
   supplied by its caller.
5. Write (if not already present from the execution step) a throwaway unit test in a scratch test
   project or inline test run: construct ControlGate with fake IAuthorityResolver/IScopePathProvider/
   registry-lookup delegate/permission-check returning controlled fixed answers; confirm
   EvaluateAsync returns Allowed below threshold, the correct *Required variant above it per
   mechanism, and Denied when the permission check fails. Delete the scratch project after if one
   was created for this check only (keep it if E9 would reuse it).

Decision: All 5 pass -> proceed to E3. Any fail -> fix first.
```

---

## SLICE E3 — Generic maker-checker engine

### EXECUTION PROMPT E3

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §3/§4. E2 complete. Source reference:
omni-api src/Omni.Domain/Administration/Aggregates/PendingApproval/PendingApproval.cs and
src/Omni.Application/Administration/Controls/MakerCheckerGate.cs.

Goal: the generic maker-checker engine, ported with its invariants intact, on this library's own
base type.

1. In src/Crestacle.Sentinel.Controls/, port PendingApproval as a sealed class extending
   Crestacle.Sentinel.Core.Entities.Entity<Guid> (NOT any host's AggregateRoot — design.md §5
   decision 4). Keep every field and method from the source (OperationKey, ScopeId [renamed from
   ServiceUnitId], TenantId [renamed from FacilityId — this is just an audit/filing field on the
   aggregate itself, distinct from the ScopePathProvider mechanism], SubjectType, SubjectId,
   PayloadJson, MakerUserId, CreatedAt, Status, CheckerUserId, DecidedAt, DecisionReason, ExpiresAt,
   RequiresFacilityLevelApprover [rename to RequiresEscalatedApprover], ApprovalNote), Create/
   Approve/Reject/Cancel/Withdraw/SetApprovalNote, and the checker != maker guard. ApprovalStatus
   enum ports as-is.

2. IPendingApprovalRepository: port the interface shape (GetAsync, GetPendingByOperationAndSubjectAsync,
   ListByScope-equivalent, AddAsync, Update, Delete) — no EF implementation here (that's E3's
   .EntityFramework half, or defer the EF implementation to a dedicated step 4 below in the same
   slice, in the .EntityFramework project).

3. MakerCheckerGate/IMakerCheckerGate: port RouteAsync, with ServiceUnitId -> ScopeId and
   FacilityId -> TenantId renames, and RequiresFacilityLevelApprover -> RequiresEscalatedApprover.
   Keep the idempotent-resubmit check (GetPendingByOperationAndSubjectAsync), the audit log call
   (take IAuditLogService-equivalent as a host-supplied interface — define a minimal
   IControlsAuditSink { Task LogAsync(string entityType, Guid entityId, string action, string?
   newValue, CancellationToken ct); } in this library rather than depending on any host's
   IAuditLogService), and the unit-of-work save (define IControlsUnitOfWork { Task SaveChangesAsync
   (CancellationToken ct); } similarly minimal).

4. IApprovableOperation: port as-is (OperationKey, ApplyAsync(PendingApproval, ct)).

5. In src/Crestacle.Sentinel.Controls.EntityFramework/: EF configuration for PendingApproval
   (table name "pending_approvals" under whatever schema convention this library's EF package
   chooses — check Crestacle.Sentinel.EntityFramework's existing schema/table naming convention and
   match it), a migration-generation-ready configuration (do NOT generate the migration itself yet —
   that happens inside each CONSUMING host's own DbContext, this package only ships the
   IEntityTypeConfiguration), and a default EF-backed IPendingApprovalRepository implementation.

Build: dotnet build Bedrock.slnx — zero errors, zero warnings.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e3): generic maker-checker engine (PendingApproval + MakerCheckerGate)"
git push origin dev
```

### VALIDATION PROMPT E3

```
Verify Slice E3. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings.
2. PendingApproval extends Crestacle.Sentinel.Core.Entities.Entity<Guid> — grep confirms no
   reference to any Omni.* or Bursary.* type anywhere in this library.
3. Checker != maker is enforced inside the aggregate itself (Approve/Reject throw if
   checkerUserId == MakerUserId), not only in MakerCheckerGate — defence in depth, matching the
   source's own design.
4. MakerCheckerGate.RouteAsync: a fake IControlGate returning ApprovalRequired results in a new
   PendingApproval row via a fake IPendingApprovalRepository + a call to the fake audit sink +ount
   unit-of-work save; a second call for the same operation/subject with an existing Pending row
   returns the existing approval id without creating a duplicate (idempotency preserved).
5. IApprovableOperation has exactly the two members from the source (OperationKey, ApplyAsync) —
   no extra coupling introduced.
6. The EF configuration in Crestacle.Sentinel.Controls.EntityFramework builds; table/schema naming
   matches this library's existing EF convention (verify against Crestacle.Sentinel.EntityFramework's
   actual configurations, not assumed).

Decision: All 6 pass -> proceed to E4. Any fail -> fix first.
```

---

## SLICE E4 — Co-sign and step-up adapters

### EXECUTION PROMPT E4

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §7a's resolution of Q1 (locked: ship a default) before starting. E3 complete.
Source reference: omni-api's ICoSignContext.cs, IStepUpContext.cs, ControlGate.EvaluateFourEyesAsync,
and SentinelCoSignContext.cs — but see the correction in step 3 below before porting its token
validation.

Goal: the four-eyes and step-up bridges — step-up should be nearly free (Bedrock already has the
re-auth mechanism in this same repo); co-sign ships a default too, per §7a Q1.

1. In src/Crestacle.Sentinel.Controls/: port ICoSignContext { Task<CoSignOutcome> EvaluateAsync
   (string operationKey, Guid scopeId, CancellationToken ct); } as-is (interface only, here,
   regardless of §7a's answer — the default implementation, if any, belongs in the AspNetCore
   package per step 3).

2. In src/Crestacle.Sentinel.Controls/: port IStepUpContext { bool HasFreshStepUp(); string?
   StepUpReference(); } as-is (interface here; default implementation in the AspNetCore package).

3. In src/Crestacle.Sentinel.Controls.AspNetCore/:
   - Default IStepUpContext implementation wrapping Crestacle.Bedrock.AspNetCore's existing
     StepUpService (find it in src/Crestacle.Bedrock.AspNetCore/Services/StepUpService.cs and its
     IStepUpService interface in Crestacle.Bedrock.Core) — read the current request's step-up proof
     via whatever mechanism RequiresStepUpAttribute already uses, so this is a thin adapter, not new
     logic.
   - A default ICoSignContext implementation reading a second bearer token from an "X-CoSign-Token"
     request header, then checking co-signer != actor via the current user context. CORRECTION vs.
     the source: do NOT port omni's SentinelCoSignContext.cs token-validation block verbatim — it
     hand-rolls a JwtSecurityTokenHandler + TokenValidationParameters instead of reusing Bedrock's
     own validator, which is the one wart §7a Q1 flagged while confirming both hosts are otherwise
     identical here (both only set opts.Jwt.SigningKey on a shared Crestacle.Bedrock options object;
     neither reimplements validation). Find and call whatever Crestacle.Bedrock.Core/AspNetCore
     already exposes for validating an access token (the same code path the primary-bearer auth
     pipeline uses) instead of constructing TokenValidationParameters here a second time. After
     validating, delegate the authority/witness checks to IAuthorityResolver — never an inline
     position lookup like the source's EffectivePositionAsync (that only existed because the port
     didn't exist yet in omni).

4. ControlGate's EvaluateFourEyesAsync path (from E2): confirm it already calls ICoSignContext
   without caring which implementation is wired — no change should be needed here if E2 was done
   correctly; if a change IS needed, that's a signal E2 under-abstracted this and should be fixed
   there, not patched around here.

Build: dotnet build Bedrock.slnx — zero errors, zero warnings.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e4): step-up adapter onto Bedrock + co-sign bridge"
git push origin dev
```

### VALIDATION PROMPT E4

```
Verify Slice E4. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings.
2. The default IStepUpContext implementation calls into Crestacle.Bedrock.AspNetCore's existing
   StepUpService — grep confirms no new token type, no new auth stack was introduced (design.md's
   whole premise for step-up is "already free").
3. A working default ICoSignContext ships (per §7a Q1), documented with its request-carriage
   convention (X-CoSign-Token header), and its token validation calls Bedrock's own validator — grep
   confirms no second hand-rolled JwtSecurityTokenHandler/TokenValidationParameters block was
   introduced (the correction step 3 of the execution prompt called for).
4. ControlGate (from E2) required no changes to consume either implementation — if it did, note
   why and confirm the fix belongs conceptually in E2's abstraction, not a special case here.

Decision: All 4 pass -> proceed to E5. Any fail -> fix first.
```

---

## SLICE E5 — Threshold override storage

### EXECUTION PROMPT E5

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §3. E2-E4 complete (IControlledOpThresholdRepository's interface already exists from
E2). Source reference: omni-api's ControlledOpThreshold aggregate and ControlledOpThresholdConfiguration.

Goal: the storage-backed half of threshold/mechanism/authority overrides.

1. In src/Crestacle.Sentinel.Controls/: port the ControlledOpThreshold aggregate (on
   Crestacle.Sentinel.Core.Entities.Entity<Guid>) — fields: ScopeId (renamed from FacilityId),
   OperationKey, Threshold?, EscalationThreshold?, MechanismOverride (ControlMechanism?),
   CheckerAuthorityOverride (IAuthorityRequirement?, nullable reference since not every op needs an
   override). Keep it a plain mutable-via-method aggregate matching the source's shape (likely a
   simple record-like entity with an Update method — check the source file for its actual mutation
   API before assuming a factory-only shape).

2. In src/Crestacle.Sentinel.Controls.EntityFramework/: EF configuration for ControlledOpThreshold,
   a default IControlledOpThresholdRepository implementation (GetAsync by (scopeId, operationKey),
   AddAsync, Update, Delete, and a ListByScopeAsync for the eventual admin screen).

3. Confirm ControlThresholdResolver (from E2) actually resolves against this repository correctly
   now that a real implementation exists — wire a quick integration-style test (in-memory EF
   provider is fine) proving: no override -> registry default; an override on the first scope-path
   element wins over one on a later element; a null field on a found override still falls through to
   the registry default for that specific field (mirroring omni's per-field ?? fallback, not an
   all-or-nothing override row).

Build: dotnet build Bedrock.slnx — zero errors, zero warnings.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e5): ControlledOpThreshold storage + EF repository"
git push origin dev
```

### VALIDATION PROMPT E5

```
Verify Slice E5. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings.
2. ControlledOpThreshold uses ScopeId, not FacilityId; EF configuration + repository exist in the
   EntityFramework package.
3. Per-field fallback confirmed by a test: an override row with only Threshold set still falls
   through to the registry default for MechanismOverride/CheckerAuthorityOverride — not an
   all-or-nothing row.
4. Scope-path ordering confirmed by a test: an override on a more-specific scope id wins over one
   on a less-specific id further down IScopePathProvider's returned list.

Decision: All 4 pass -> proceed to E6. Any fail -> fix first.
```

---

## SLICE E6 — Break-glass primitive

### EXECUTION PROMPT E6

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §2/§5 decision 2 (Scope becomes string). E5 complete. Source reference: omni-api's
BreakGlassEvent.cs.

Goal: the generic emergency-override aggregate and its review workflow, ported with Scope
generalized to a free-text string.

1. In src/Crestacle.Sentinel.Controls/: port BreakGlassEvent (on Entity<Guid>) — fields: UserId,
   ScopeId (renamed from ServiceUnitId), TenantId (renamed from FacilityId), Scope (string, NOT
   omni's BreakGlassScope enum), SubjectRef, Reason, StepUpReference, GrantedAt, ExpiresAt,
   ReviewedAt?, ReviewedByUserId?, ReviewOutcome? (keep this as a small library-owned enum —
   Approved/Flagged-equivalent outcomes are genuinely generic, unlike Scope), ReviewNotes. Port
   Create (same validation guards: reason mandatory, step-up reference mandatory, ExpiresAt >
   GrantedAt), IsActive(now), IsReviewed, Review(...) as-is.

2. IBreakGlassRepository (new interface, not present verbatim in the source — check whether omni
   actually has one or accesses the aggregate directly via DbContext; if the latter, define the
   interface fresh here following this library's existing repository-interface shape from E3/E5).

3. In src/Crestacle.Sentinel.Controls.EntityFramework/: EF configuration + default repository
   implementation.

4. Document in a doc comment on BreakGlassEvent that Scope is intentionally a free-text string, not
   an enum, specifically because it must not couple this library to any one host's feature set — and
   that each host is expected to validate Scope against its own known set of break-glass-eligible
   operations before calling Create (the library itself does not validate Scope's content).

Build: dotnet build Bedrock.slnx — zero errors, zero warnings.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e6): generic break-glass primitive + review workflow"
git push origin dev
```

### VALIDATION PROMPT E6

```
Verify Slice E6. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings.
2. BreakGlassEvent.Scope is typed string; grep confirms no BreakGlassScope-style enum exists in
   this library.
3. Create enforces: reason mandatory, step-up reference mandatory, ExpiresAt > GrantedAt (same
   guards as the source) — confirmed by a quick test exercising each guard.
4. IsActive(now) is time-only and independent of review state, matching the source's documented
   intent (review is governance-only, does not extend/shorten the window).
5. EF configuration + repository exist in the EntityFramework package.

Decision: All 5 pass -> proceed to E7. Any fail -> fix first.
```

---

## SLICE E7 — Admin policy contracts + `[RequiresControl]`

### EXECUTION PROMPT E7

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §7a's resolution of Q5. E6 complete. Source reference: omni-api's
GetControlledOperationsQuery/GetControlledOperationsQueryHandler, SetControlledOpThresholdCommand,
and how step-up's RequiresStepUpAttribute is implemented (for the filter pattern to mirror).

Goal: the generic admin-policy data contract, and an action filter that runs the gate before a
controlled endpoint executes (so a consuming host doesn't need to hand-call IControlGate in every
handler).

1. In src/Crestacle.Sentinel.Controls/: define ControlledOperationPolicyDto(string OperationKey,
   string Feature, ControlMechanism EffectiveMechanism, decimal? EffectiveThreshold, decimal?
   EffectiveEscalationThreshold, bool HasScopeOverride) — fully generic, no reference to any host's
   registry type (per §7a Q5). A host's query handler builds a list of these by walking its own
   registry + this library's IControlThresholdResolver; this library does not ship the query handler
   itself (it cannot — it doesn't have a registry to iterate).

2. In src/Crestacle.Sentinel.Controls.AspNetCore/: a RequiresControlAttribute(string operationKey)
   action filter, structured like Crestacle.Bedrock.AspNetCore/Authorization/RequiresStepUpAttribute.cs
   (read it first). On a controlled action:
   - Resolve IControlGate from DI, build a ControlRequest from route/query values the attribute is
     configured to read (operationKey is static on the attribute; ScopeId/Amount/SubjectId need a
     documented convention for where the filter reads them from the request — e.g. route value names
     "scopeId"/"amount"/"subjectId" by default, overridable via attribute properties).
   - On Denied -> short-circuit 403 with the reason. On StepUpRequired/ApprovalRequired/CoSignRequired
     -> short-circuit with a response shape carrying enough for the client to act (mirror
     RequiresStepUpAttribute's existing challenge-response shape where this overlaps it).
   - On Allowed -> let the action execute normally.
   Document clearly that for MakerChecker/FourEyes mechanisms, many real endpoints will prefer
   calling IMakerCheckerGate/IControlGate directly inside the handler (to submit a PendingApproval
   or capture a co-sign payload) rather than this filter — the filter suits StepUp and simple
   Allowed/Denied cases best. Say so in a doc comment; do not force every mechanism through the
   filter if that distorts the handler.

Build: dotnet build Bedrock.slnx — zero errors, zero warnings.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e7): admin policy DTO + RequiresControlAttribute"
git push origin dev
```

### VALIDATION PROMPT E7

```
Verify Slice E7. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings.
2. ControlledOperationPolicyDto has no reference to any host-specific type — grep confirms it's
   pure primitives + this library's own enums.
3. RequiresControlAttribute follows the same structural pattern as RequiresStepUpAttribute (read
   both side by side to confirm) — short-circuits correctly on each ControlDecision variant.
4. The doc comment honestly scopes the filter's fit (StepUp/simple cases) vs. direct
   IMakerCheckerGate/IControlGate calls (MakerChecker/FourEyes) — this is a judgment call the
   execution prompt asked for; confirm it was actually made, not glossed over.

Decision: All 4 pass -> proceed to E8. Any fail -> fix first.
```

---

## SLICE E8 — DI wiring + docs + package version

### EXECUTION PROMPT E8

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
Read design.md §7a's resolution of Q4. E7 complete.

Goal: one-call DI registration per package, docs updated, version bumped — the package is now
installable and usable end to end (validated in E9).

1. AddSentinelControls(this IServiceCollection services, Func<string, ControlledOperation?>
   registryLookup) in Crestacle.Sentinel.Controls — registers IControlGate/ControlGate,
   IControlThresholdResolver/ControlThresholdResolver, IMakerCheckerGate/MakerCheckerGate, binding
   the registryLookup delegate from E2. Follow the existing AddBedrockWithSentinel-style extension
   method naming/shape (read it first).

2. AddSentinelControlsEntityFramework(this IServiceCollection services) in
   Crestacle.Sentinel.Controls.EntityFramework — registers the three EF repository implementations
   (PendingApproval, ControlledOpThreshold, BreakGlassEvent) + their IEntityTypeConfiguration
   registrations (following however Crestacle.Sentinel.EntityFramework's own extension method applies
   configurations to a consuming DbContext — likely via an ApplyConfigurationsFromAssembly call the
   host's own DbContext.OnModelCreating invokes, not something this library does to the host's model
   directly. Confirm the actual mechanism Sentinel.EntityFramework uses and match it exactly).

3. AddSentinelControlsAspNetCore(this IServiceCollection services) in
   Crestacle.Sentinel.Controls.AspNetCore — registers IStepUpContext's default implementation and,
   per §7a Q1, ICoSignContext's default implementation if one was built in E4.

4. Update docs/architecture.md and docs/api-reference.md (root docs/, not the features/ folder) with
   a new section covering the Controls packages — what they are, the two ports a host must
   implement, and a link to docs/features/sentinel-controls/design.md for the full rationale.

5. Bump Directory.Build.props's VersionPrefix per §7a's Q4 resolution.

6. dotnet pack each of the three new projects; confirm the resulting .nupkg files land in
   artifacts/ alongside the existing packages (same mechanism omni-api's and bursary-api's
   nuget.config local-bedrock source already points at).

Build: dotnet build Bedrock.slnx — zero errors, zero warnings. dotnet pack succeeds for all three
new projects.

Commit:
git add -A
git commit -m "feat(sentinel-controls-e8): DI wiring extensions + docs + version bump"
git push origin dev
```

### VALIDATION PROMPT E8

```
Verify Slice E8. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings.
2. dotnet pack succeeds for Crestacle.Sentinel.Controls, .EntityFramework, .AspNetCore; the three
   .nupkg files appear in artifacts/.
3. Each AddSentinelControls* extension method follows the existing AddBedrockWithSentinel naming/
   registration pattern (side-by-side comparison, not assumed).
4. docs/architecture.md and docs/api-reference.md both mention the Controls packages and link to
   docs/features/sentinel-controls/design.md.
5. VersionPrefix reflects §7a's Q4 decision.

Decision: All 5 pass -> proceed to E9. Any fail -> fix first.
```

---

## SLICE E9 — Validation harness

### EXECUTION PROMPT E9

```
Working directory: /Users/kstanleyk/Developer/libs/bedrock
E8 complete. This is the slice that proves the library actually works for a host that isn't omni —
bedrock has no running application of its own, so this replaces the "run the API on <real db>" step
every omni-api/bursary-api slice ends on.

1. Add a new sample project under samples/ (mirroring Embedded/Standalone/ExternalIdp's existing
   shape and csproj conventions) — name it samples/ControlsDemo. It implements, minimally:
   - A fake IAuthorityResolver with two canned requirement types (e.g. a "MinLevel(int)" requirement
     and a simple "HasPermission(string)" requirement) resolved against a hardcoded in-memory
     user/level map.
   - A fake IScopePathProvider returning a two-element path (proves the walk-up logic works for more
     than the one-element case both real hosts use today — this is the one scenario neither omni nor
     bursary currently exercises, so the sample MUST cover it).
   - A tiny registry (3-4 ControlledOperation rows covering all four mechanisms) and one
     IApprovableOperation implementation.
   - A console or minimal-API harness exercising, end to end, against an in-memory/SQLite EF
     provider: an uncontrolled op (Allowed), a step-up op (denied without proof, allowed with a
     faked-fresh proof), a maker-checker op (submit -> approve by a different qualifying user ->
     IApprovableOperation.ApplyAsync runs), a four-eyes op (denied without co-sign, allowed with a
     faked valid co-sign), a threshold override on the second (less-specific) scope-path element
     being correctly overridden by one on the first (more-specific) element, and a break-glass grant
     + review.

2. Add tests/Crestacle.Sentinel.Controls.Tests (mirroring tests/Crestacle.Sentinel.Tests's shape) —
   unit tests for ControlGate's decision branches (one test per ControlDecision variant),
   MakerCheckerGate's idempotent-resubmit behavior, PendingApproval's checker != maker guard,
   BreakGlassEvent's guard clauses and IsActive/IsReviewed semantics. Add this project to
   Bedrock.slnx under /tests/.

Build: dotnet build Bedrock.slnx — zero errors, zero warnings. dotnet test — zero failures (new
project included). Run the ControlsDemo sample manually and confirm each scenario in step 1 behaves
as described.

Commit:
git add -A
git commit -m "test(sentinel-controls-e9): validation harness (sample host + unit tests)"
git push origin dev
```

### VALIDATION PROMPT E9

```
Verify Slice E9. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings. dotnet test — zero failures.
2. samples/ControlsDemo exists, added to Bedrock.slnx, and its two-element IScopePathProvider
   scenario specifically proves the scope-path walk works beyond the one-element case — this is the
   one thing neither omni nor bursary exercises today, so confirm it was not skipped or faked away.
3. Running the sample manually confirms all six scenarios from the execution prompt (uncontrolled,
   step-up, maker-checker, four-eyes, scope-path override precedence, break-glass) behave correctly.
4. tests/Crestacle.Sentinel.Controls.Tests covers ControlGate's five decision branches,
   MakerCheckerGate idempotency, PendingApproval's checker != maker guard, and BreakGlassEvent's
   guards + IsActive/IsReviewed.

Decision: All 4 pass -> run COMPLETION. Any fail -> fix first.
```

---

## COMPLETION PROMPT

```
E0-E9 complete. Working directory: /Users/kstanleyk/Developer/libs/bedrock

1. dotnet build Bedrock.slnx — zero errors, zero warnings. dotnet test — zero failures across the
   whole solution, including the pre-existing Bedrock/Sentinel test projects (confirm nothing in
   those regressed).
2. dotnet pack succeeds for all three new packages; .nupkg files present in artifacts/.
3. The two couplings design.md §2 identified (UnitPosition, two-field FacilityId/ServiceUnitId) are
   verifiably absent from the library (grep, not just memory of E2's validation).
4. samples/ControlsDemo exercises all four mechanisms + break-glass + the two-element scope-path
   case end to end.
5. Root README.md and docs/architecture.md/docs/api-reference.md reflect the three new packages.
6. git log on dev shows the E0-E9 slice commits.

If all 6 pass: the extraction is done. omni-api/docs/features/migrate-to-sentinel-controls/ may
begin. Update docs/features/sentinel-controls/roadmap.md (tick E0-E9 and Completion).
```
