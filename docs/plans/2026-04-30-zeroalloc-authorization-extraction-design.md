# ZeroAlloc.Authorization Extraction — Design

**Status:** approved 2026-04-30
**Source repo:** `C:\Projects\Prive\AI.Sentinel\` (currently 1.4.1)
**Target repo:** `C:\Projects\Prive\ZeroAlloc\` (monorepo; each package = top-level dir with own `.slnx`)
**Backlog item:** "`ZeroAlloc.Authorization.Abstractions` extraction" (Policy & Authorization theme)

---

## Problem

AI.Sentinel currently owns five generic authorization primitives in `src/AI.Sentinel/Authorization/`:

- `ISecurityContext` — caller identity (Id + Roles + Claims)
- `IAuthorizationPolicy` — `bool IsAuthorized(ISecurityContext)` rule contract
- `AuthorizeAttribute` — declarative `[Authorize("policy")]` binding for AIFunction-bound methods
- `AuthorizationPolicyAttribute` — `[AuthorizationPolicy("name")]` policy registration
- `AnonymousSecurityContext` — canonical empty-caller singleton

These primitives are not AI.Sentinel-specific. A future `ZeroAlloc.Mediator.Authorization` package will want the same `ISecurityContext` / `IAuthorizationPolicy` / `[Authorize]` shape so a single policy class works for both worlds (LLM tool-call gates *and* mediator request gates).

Without extraction, every cross-cutting policy has to be written twice (or take a hard reference on AI.Sentinel from non-AI projects, which is wrong).

## Goals

1. Move the 5 primitives into a new standalone NuGet package owned by the ZeroAlloc ecosystem.
2. Zero breaking change for existing AI.Sentinel 1.4.x consumers — recompile and ship.
3. Establish the v1.0 shape including the async overload, so future Mediator.Authorization can adopt it without a v2 break.

## Non-goals

- Designing `ZeroAlloc.Mediator.Authorization` (separate future work in the Mediator repo).
- Moving `IToolCallSecurityContext`, `AuthorizationDecision`, `IToolCallGuard`, `DefaultToolCallGuard`, `AuthorizationChatClient`, or the concrete policy implementations — these are all tool-call-specific and stay in AI.Sentinel.
- Source generators (no `ZeroAlloc.Authorization.SourceGen` yet — defer until a real consumer needs one).

---

## Design decisions

### D1. Package shape — single `ZeroAlloc.Authorization` (no `.Abstractions` suffix)

The 5 primitives total ~50 lines and have no runtime. The Microsoft `*.Abstractions` convention exists when there's a separate runtime to keep dependency-free; we have no runtime. Matches the simpler `ZeroAlloc.Inject` shape, not the multi-subpackage `ZeroAlloc.Mediator` shape.

**Rejected alternatives:**
- `ZeroAlloc.Authorization.Abstractions` — over-engineered for a 5-type interface package.
- `ZeroAlloc.Authorization` *parent* + `.Abstractions` *child* (Mediator pattern) — only justified if a runtime grows; YAGNI.

If a runtime ever appears (built-in policy registry, default impls), it folds into the same package.

### D2. Type set — 5 primitives only

Move:
- `ISecurityContext`
- `IAuthorizationPolicy`
- `AuthorizeAttribute`
- `AuthorizationPolicyAttribute`
- `AnonymousSecurityContext`

Stay in AI.Sentinel:
- `IToolCallSecurityContext` — extends `ISecurityContext` with `string ToolName` + `JsonElement Args`. Late-bound, JSON-shaped, brings a `System.Text.Json` dep. Mediator's analogous extension would be generic over `TRequest` (typed, zero-alloc) — different shape, can't unify.
- `AuthorizationDecision` (sealed hierarchy with `RequireApprovalDecision`) — AI.Sentinel-specific PIM workflow concept.
- `IToolCallGuard` + `DefaultToolCallGuard` — tool-call dispatch.
- `AuthorizationChatClient` + builder extension — `IChatClient` middleware.
- `Policies/AdminOnlyPolicy.cs`, `Policies/NoSystemPathsPolicy.cs` — concrete impls; consumers provide their own.

The base `ISecurityContext` is the only shape both worlds share (caller identity). Both consumers downcast to their own context flavour inside the policy's `IsAuthorized(ISecurityContext)` body.

### D3. AI.Sentinel migration — Option A: `[TypeForwardedTo]`

Append to `src/AI.Sentinel/AssemblyAttributes.cs`:

```csharp
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.ISecurityContext))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.IAuthorizationPolicy))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AuthorizeAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AuthorizationPolicyAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AnonymousSecurityContext))]
```

Existing consumers' `using AI.Sentinel.Authorization;` keeps compiling because the CLR redirects type loads at the assembly level. Recompile and ship — zero source change required downstream.

Cost: the `AI.Sentinel.Authorization` namespace lives forever as a forwarder. This is fine — type-forwarders are exactly the mechanism MS uses for these splits (e.g., `System.Memory` types forwarded across assemblies for years), and they cost nothing at runtime.

**Rejected alternatives:**
- `[Obsolete]` shim subclasses (Option B) — adds compile noise without enough benefit; consumers who don't update their `using` statements still see warnings. TypeForwardedTo is invisible.
- Hard move forcing `using ZeroAlloc.Authorization;` (Option C) — unnecessary breaking change. AI.Sentinel 2.0 should be reserved for actual API breaks.

### D4. Async `IAuthorizationPolicy` — bundle into v1

The v1 shape:

```csharp
namespace ZeroAlloc.Authorization;

public interface IAuthorizationPolicy
{
    bool IsAuthorized(ISecurityContext ctx);

    /// <summary>I/O-bound override point. Default delegates to sync.</summary>
    ValueTask<bool> IsAuthorizedAsync(ISecurityContext ctx, CancellationToken ct = default)
        => ValueTask.FromResult(IsAuthorized(ctx));
}
```

- `ValueTask<bool>` — fits the ZeroAlloc zero-alloc ethos (no Task allocation when sync path returns).
- Default interface method delegates to `IsAuthorized(ctx)` — existing AI.Sentinel sync-only impls (`AdminOnlyPolicy`, `NoSystemPathsPolicy`) keep working unchanged.
- `CancellationToken ct = default` — required for any I/O-bound impl that has to honor host-side cancellation.

Backlog explicitly required "coordinate with `ZeroAlloc.Mediator.Authorization` design before changing the interface" — but Mediator.Authorization doesn't exist yet, so the gate can't be met. Adding a default-impl async overload now is non-breaking and saves a future minor version bump. Rejecting "defer" here.

---

## Architecture

### New repo dir layout

```
C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\
├── ZeroAlloc.Authorization.slnx
├── Directory.Build.props
├── README.md
├── CHANGELOG.md
├── LICENSE
├── GitVersion.yml         (matches sibling packages)
├── global.json
├── src\
│   └── ZeroAlloc.Authorization\
│       ├── ZeroAlloc.Authorization.csproj   (net8.0;net10.0)
│       ├── ISecurityContext.cs
│       ├── IAuthorizationPolicy.cs
│       ├── AuthorizeAttribute.cs
│       ├── AuthorizationPolicyAttribute.cs
│       └── AnonymousSecurityContext.cs
└── tests\
    └── ZeroAlloc.Authorization.Tests\
        ├── ZeroAlloc.Authorization.Tests.csproj   (net8.0;net10.0)
        ├── AnonymousSecurityContextTests.cs
        ├── AttributeTests.cs
        └── AsyncDefaultBehaviourTests.cs
```

Match the conventions of sibling packages (`Directory.Build.props`, `GitVersion.yml`, `global.json`, top-level `README.md` with the standard badge block).

### AI.Sentinel changes

- Delete `src/AI.Sentinel/Authorization/{ISecurityContext,IAuthorizationPolicy,AuthorizeAttribute,AuthorizationPolicyAttribute,AnonymousSecurityContext}.cs`.
- Append 5 `[assembly: TypeForwardedTo(...)]` lines to `src/AI.Sentinel/AssemblyAttributes.cs`.
- Add `<PackageReference Include="ZeroAlloc.Authorization" Version="1.0.*" />` to `src/AI.Sentinel/AI.Sentinel.csproj`.
- `IToolCallSecurityContext.cs` keeps its `: ISecurityContext` inheritance — the type now resolves through the package.
- All existing test files are unchanged. The `using AI.Sentinel.Authorization;` statements continue to resolve through the type-forwarder.

### Versioning

- **ZeroAlloc.Authorization 1.0.0** — first release. Standalone GitVersion / release-please workflow in the new repo dir.
- **AI.Sentinel 1.5.0** — minor bump (additive: gains a NuGet dependency, no breaking change).

---

## Sequencing constraint

ZeroAlloc.Authorization 1.0.0 **must ship to nuget.org before AI.Sentinel 1.5.0's CI runs**, otherwise NuGet restore on the AI.Sentinel build fails with "package not found".

Local development bridge: while iterating in the same session, AI.Sentinel can use a `<ProjectReference>` to the cross-repo path (`..\..\ZeroAlloc\ZeroAlloc.Authorization\src\ZeroAlloc.Authorization\ZeroAlloc.Authorization.csproj`). Switch to `<PackageReference>` only on the commit that goes to release-please.

The implementation plan must include this as an explicit ordered step.

---

## Testing strategy

### ZeroAlloc.Authorization tests (new)

Small — the package is mostly contracts:

- `AnonymousSecurityContext_Singleton_HasEmptyRolesAndClaims` — verifies the canonical empty-caller invariant.
- `AuthorizeAttribute_StoresPolicyName` — round-trip the constructor-set property.
- `AuthorizationPolicyAttribute_StoresName` — round-trip the constructor-set property.
- `IAuthorizationPolicy_AsyncDefault_DelegatesToSync` — sync-only impl must work via `IsAuthorizedAsync` thanks to default interface method.
- `IAuthorizationPolicy_AsyncOverride_BypassesSync` — explicit async override doesn't invoke the sync method.
- `IAuthorizationPolicy_AsyncCancellation_PropagatesToken` — `CancellationToken` flows through.

### AI.Sentinel tests (existing, unchanged)

The full suite (~700 tests) must pass untouched after the migration. The deleted-files' types resolve via the type-forwarder; existing tests reference them through the `AI.Sentinel.Authorization` namespace which keeps compiling against the forwarded names.

### Cross-repo integration verification

Manually verify (or as a one-shot CI step) that consuming `ZeroAlloc.Authorization` from AI.Sentinel via `<PackageReference>` produces a working build identical to the `<ProjectReference>` development version.

---

## Out of scope (for this design)

- `ZeroAlloc.Mediator.Authorization` package — separate work in the Mediator repo, will consume `ZeroAlloc.Authorization` 1.0+.
- Source generator (`ZeroAlloc.Authorization.SourceGen`) — backlog item "Source-gen-driven policy name lookup" stays as a follow-up.
- `[Authorize]` attribute discovery for AIFunction-bound methods — AI.Sentinel-side runtime work, separate backlog item.
- Cross-package CI workflow setup — out of scope; each package keeps its own pipeline.

---

## Implementation order

1. Build `ZeroAlloc.Authorization` 1.0.0 in its own repo (new dir, scaffold from sibling, add 5 types, add tests, README, CHANGELOG, NuGet metadata).
2. Push to nuget.org as 1.0.0.
3. On AI.Sentinel branch: delete the 5 source files, add type-forwarders, add `<PackageReference>`, run full test suite, commit.
4. Open AI.Sentinel PR; release-please opens 1.5.0 PR after merge; that ships to nuget.org.

The detailed step-by-step plan goes in the implementation plan (next skill: writing-plans).
