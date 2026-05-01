# Async + Structured Authorization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or superpowers:subagent-driven-development for same-session execution) to implement this plan task-by-task.

**Goal:** Switch `DefaultToolCallGuard` from synchronous `policy.IsAuthorized(ctx)` to asynchronous structured `policy.EvaluateAsync(ctx, ct)`, surfacing the policy-supplied `Code` + `Reason` from `ZeroAlloc.Authorization.AuthorizationFailure` through every consumer-visible surface (decision, audit, hook receipts, MCP error body, dashboard).

**Architecture:** Strictly additive. `DenyDecision` gains a `Code` field with default `"policy_denied"`; `AuditEntry` gains an optional `PolicyCode` property; the audit-store schema gains a `policy_code TEXT NOT NULL DEFAULT 'policy_denied'` column via a non-locking `ALTER TABLE` migration. Existing sync-only `IAuthorizationPolicy` implementations work unchanged through ZeroAlloc.Authorization 1.1's default-interface-method bridges.

**Tech Stack:** .NET 8 / 10 multi-target, xUnit, ZeroAlloc.Authorization 1.1.0 (already a `<PackageReference>` in `src/AI.Sentinel/AI.Sentinel.csproj`), conventional commits, release-please.

**Design doc:** [`docs/plans/2026-05-01-async-structured-authorization-design.md`](2026-05-01-async-structured-authorization-design.md). Read that first for the rationale behind every decision below.

**Branch:** `feat/async-structured-authorization` (already created, off main, has the design doc commit `cb3990b`).

---

## Phase 0 — Preflight

### Task 0.1: Baseline + safety grep

**Step 1: Confirm branch state.**

```bash
cd C:/Projects/Prive/AI.Sentinel
git status
git branch --show-current
git log --oneline -3
```
Expected: branch `feat/async-structured-authorization`, HEAD `cb3990b` (design doc), parent on main.

**Step 2: Baseline the test counts.**

```bash
dotnet build AI.Sentinel.slnx --nologo 2>&1 | tail -5
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected per-project pass counts (must remain unchanged after every Phase-1/2/3/4 task except where the plan explicitly adds tests):
- `AI.Sentinel.Tests.dll`: 583
- `AI.Sentinel.Approvals.Sqlite.Tests.dll`: 14
- `AI.Sentinel.Approvals.EntraPim.Tests.dll`: 19
- `AI.Sentinel.Detectors.Sdk.Tests.dll`: 29
- `AI.Sentinel.OpenTelemetry.Tests.dll`: 10
- `AI.Sentinel.Sqlite.Tests.dll`: 10
- `AI.Sentinel.AzureSentinel.Tests.dll`: 3

**Total: 668.** Final count after all tasks complete: **~680** (12 net new tests).

**Step 3: Pre-flight grep for positional `DenyDecision` deconstruction.**

```bash
grep -rn "case DenyDecision(" src tests samples --include="*.cs"
grep -rn "is DenyDecision(" src tests samples --include="*.cs"
```
Expected: zero matches. If anything turns up, those call sites must be updated to use named-property patterns BEFORE Task 1.1, otherwise the additive `Code` parameter breaks them.

No commit — preflight only.

---

## Phase 1 — Core decision model + guard call site

### Task 1.1: Add `Code` field to `DenyDecision` + `Deny` factory

**Files:**
- Modify: `src/AI.Sentinel/Authorization/AuthorizationDecision.cs`
- Test: `tests/AI.Sentinel.Tests/Authorization/AuthorizationDecisionTests.cs`

**Step 1: Write the failing tests.**

Append to `tests/AI.Sentinel.Tests/Authorization/AuthorizationDecisionTests.cs`:

```csharp
[Fact]
public void Deny_WithoutCode_AppliesDefaultPolicyDeniedCode()
{
    var deny = AuthorizationDecision.Deny("AdminOnly", "user is not admin");
    Assert.Equal("policy_denied", deny.Code);
}

[Fact]
public void Deny_WithCode_PreservesPolicySuppliedCode()
{
    var deny = AuthorizationDecision.Deny("TenantActive", "tenant evicted", "tenant_inactive");
    Assert.Equal("tenant_inactive", deny.Code);
    Assert.Equal("TenantActive", deny.PolicyName);
    Assert.Equal("tenant_evicted", deny.Reason);   // intentional typo to verify reason is also bound — fix in step 3 if it fails
}
```

(Fix the typo: the test expects `"tenant evicted"` not `"tenant_evicted"` — the second assertion verifies the existing Reason field is still bound correctly.)

**Step 2: Run tests — verify they fail.**

```bash
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~AuthorizationDecisionTests" --nologo
```
Expected: FAIL with `'DenyDecision' does not contain a definition for 'Code'`.

**Step 3: Implement.**

Replace lines 11-12 + 19-20 in `src/AI.Sentinel/Authorization/AuthorizationDecision.cs`.

Before:
```csharp
public sealed record DenyDecision(string PolicyName, string Reason) : AuthorizationDecision;
...
public static DenyDecision Deny(string policyName, string reason) =>
    new(policyName, reason);
```

After:
```csharp
/// <summary>Decision refusing the call.</summary>
/// <param name="PolicyName">Name of the denying policy.</param>
/// <param name="Reason">Human-readable reason for the denial.</param>
/// <param name="Code">Machine-readable code (e.g. "tenant_inactive", "bash_blocked"). Defaults to
/// <c>"policy_denied"</c> when the policy returned bare <c>false</c> via the sync IsAuthorized DIM bridge.</param>
public sealed record DenyDecision(string PolicyName, string Reason, string Code = "policy_denied") : AuthorizationDecision;
...
/// <summary>Builds a deny decision with the policy name, reason and code.</summary>
/// <param name="policyName">Name of the denying policy.</param>
/// <param name="reason">Human-readable reason for the denial.</param>
/// <param name="code">Machine-readable code; defaults to <c>"policy_denied"</c>.</param>
public static DenyDecision Deny(string policyName, string reason, string code = "policy_denied") =>
    new(policyName, reason, code);
```

**Step 4: Run tests — verify they pass.**

```bash
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~AuthorizationDecisionTests" --nologo
```
Expected: PASS for both new tests + all existing decision tests still green.

**Step 5: Verify the broader suite still compiles and runs.**

```bash
dotnet build AI.Sentinel.slnx --nologo 2>&1 | tail -5
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: 0 errors, 0 warnings; test counts unchanged from baseline (+ the 2 new tests in `AI.Sentinel.Tests`).

**Step 6: Commit.**

```bash
git add src/AI.Sentinel/Authorization/AuthorizationDecision.cs tests/AI.Sentinel.Tests/Authorization/AuthorizationDecisionTests.cs
git commit -m "feat(authz): add Code field to DenyDecision

Additive — default value 'policy_denied' preserves all existing
Deny(name, reason) call sites and named-property pattern matches.
Pre-flight grep confirmed zero positional DenyDecision deconstructions
in the solution."
```

---

### Task 1.2: Switch `DefaultToolCallGuard.EvaluatePolicy` to async + structured

**Files:**
- Modify: `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs` (lines ~94-119, plus the caller at the top of `AuthorizeAsync`)
- Test: `tests/AI.Sentinel.Tests/Authorization/DefaultToolCallGuardTests.cs`

**Step 1: Write the failing tests.**

Append to `tests/AI.Sentinel.Tests/Authorization/DefaultToolCallGuardTests.cs`:

```csharp
private sealed class StructuredFailurePolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ZeroAlloc.Authorization.ISecurityContext ctx) => false;
    public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
        ZeroAlloc.Authorization.ISecurityContext ctx, CancellationToken ct = default) =>
        new(UnitResult<AuthorizationFailure>.Failure(
            new AuthorizationFailure("tenant_inactive", "Tenant is in evicted state")));
}

private sealed class CancellationAwarePolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ZeroAlloc.Authorization.ISecurityContext ctx) => true;
    public async ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
        ZeroAlloc.Authorization.ISecurityContext ctx, CancellationToken ct = default)
    {
        await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
        return UnitResult<AuthorizationFailure>.Success;
    }
}

[Fact]
public async Task EvaluatePolicy_StructuredFailure_PropagatesCodeAndReasonToDecision()
{
    var guard = new DefaultToolCallGuard(
        bindings: [new ToolCallPolicyBinding("Bash", "tenant-active", null, null)],
        policiesByName: new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal)
        {
            ["tenant-active"] = new StructuredFailurePolicy(),
        },
        @default: ToolPolicyDefault.Deny,
        approvalStore: null,
        logger: null);

    var decision = await guard.AuthorizeAsync(
        new TestSecurityContext("user-1"), "Bash", JsonDocument.Parse("{}").RootElement);

    var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
    Assert.Equal("tenant_inactive", deny.Code);
    Assert.Equal("Tenant is in evicted state", deny.Reason);
    Assert.Equal("tenant-active", deny.PolicyName);
}

[Fact]
public async Task EvaluatePolicy_SyncOnlyFalsePolicy_AppliesDefaultPolicyDeniedCode()
{
    // AdminOnlyPolicy implements only IsAuthorized; the DIM bridge in ZeroAlloc.Authorization
    // produces a default failure with AuthorizationFailure.DefaultDenyCode.
    var guard = new DefaultToolCallGuard(
        bindings: [new ToolCallPolicyBinding("Bash", "admin-only", null, null)],
        policiesByName: new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal)
        {
            ["admin-only"] = new AdminOnlyPolicy(),   // sync-only, returns false for non-admin
        },
        @default: ToolPolicyDefault.Deny,
        approvalStore: null,
        logger: null);

    var decision = await guard.AuthorizeAsync(
        new TestSecurityContext("user-1"), "Bash", JsonDocument.Parse("{}").RootElement);

    var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
    Assert.Equal("policy_denied", deny.Code);   // default falls through from DIM bridge default
}

[Fact]
public async Task EvaluatePolicy_CancellationToken_PropagatesToPolicy()
{
    var guard = new DefaultToolCallGuard(
        bindings: [new ToolCallPolicyBinding("Bash", "slow", null, null)],
        policiesByName: new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal)
        {
            ["slow"] = new CancellationAwarePolicy(),
        },
        @default: ToolPolicyDefault.Deny,
        approvalStore: null,
        logger: null);

    using var cts = new CancellationTokenSource();
    cts.Cancel();
    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        await guard.AuthorizeAsync(
            new TestSecurityContext("user-1"), "Bash", JsonDocument.Parse("{}").RootElement, cts.Token));
}
```

Add the necessary `using` directives at the top of the test file:
```csharp
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;
```

**Step 2: Run tests — verify they fail.**

```bash
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~DefaultToolCallGuardTests" --nologo 2>&1 | tail -20
```
Expected: 3 NEW tests fail (assertions on `deny.Code` and the cancellation propagation).

**Step 3: Implement.**

In `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`, locate the `EvaluatePolicy` method (around line 94). Change its signature from sync to async and switch the policy invocation to `EvaluateAsync`:

Before:
```csharp
private AuthorizationDecision? EvaluatePolicy(ToolCallPolicyBinding binding, ToolCallContextWrapper ctx)
{
    if (!policiesByName.TryGetValue(binding.PolicyName, out var policy))
    {
        logger?.LogError(...);
        return AuthorizationDecision.Deny(binding.PolicyName,
            $"Policy '{binding.PolicyName}' is not registered");
    }

    bool allowed;
    try
    {
        allowed = policy.IsAuthorized(ctx);
    }
    catch (Exception ex)
    {
        logger?.LogError(ex, ...);
        return AuthorizationDecision.Deny(binding.PolicyName,
            $"Policy threw {ex.GetType().Name}");
    }

    return allowed ? null : AuthorizationDecision.Deny(binding.PolicyName, "Policy denied");
}
```

After:
```csharp
private async ValueTask<AuthorizationDecision?> EvaluatePolicyAsync(
    ToolCallPolicyBinding binding, ToolCallContextWrapper ctx, CancellationToken ct)
{
    if (!policiesByName.TryGetValue(binding.PolicyName, out var policy))
    {
        logger?.LogError("Policy '{PolicyName}' is bound to '{Pattern}' but not registered — denying.",
            binding.PolicyName, binding.Pattern);
        return AuthorizationDecision.Deny(binding.PolicyName,
            $"Policy '{binding.PolicyName}' is not registered",
            "policy_not_registered");
    }

    UnitResult<AuthorizationFailure> result;
    try
    {
        result = await policy.EvaluateAsync(ctx, ct).ConfigureAwait(false);
    }
    catch (OperationCanceledException) when (ct.IsCancellationRequested)
    {
        // Cooperative cancellation propagates — never silently denied.
        throw;
    }
#pragma warning disable CA1031 // Fail-closed: any other policy exception must deny, regardless of type.
    catch (Exception ex)
#pragma warning restore CA1031
    {
        logger?.LogError(ex, "Policy '{PolicyName}' threw — failing closed (deny).", binding.PolicyName);
        return AuthorizationDecision.Deny(binding.PolicyName,
            $"Policy threw {ex.GetType().Name}",
            "policy_exception");
    }

    if (result.IsSuccess)
    {
        return null;   // allow — policy evaluation passed
    }

    var failure = result.Error;
    return AuthorizationDecision.Deny(binding.PolicyName, failure.Reason, failure.Code);
}
```

Add at the top of the file:
```csharp
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;
```

(Both packages are transitively available via `ZeroAlloc.Authorization`, but the `using ZeroAlloc.Results;` is needed because `UnitResult<T>` lives there.)

**Step 4: Update the caller in `AuthorizeAsync`.**

Find the call site (single, in `AuthorizeAsync` around line ~50):

Before:
```csharp
var decision = EvaluatePolicy(binding, ctx);
if (decision is not null) return decision;
```

After:
```csharp
var decision = await EvaluatePolicyAsync(binding, ctx, ct).ConfigureAwait(false);
if (decision is not null) return decision;
```

**Step 5: Verify cancellation token reaches the new method.**

The `AuthorizeAsync` method already takes a `CancellationToken ct = default` parameter — confirm the value is in scope at the call site. If not, thread it through the surrounding method's signature.

**Step 6: Run the new tests — verify they pass.**

```bash
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~DefaultToolCallGuardTests" --nologo
```
Expected: PASS for all 3 new tests + all existing guard tests still green.

**Step 7: Update existing tests that asserted against `"Policy denied"` literal.**

Run:
```bash
grep -rn "\"Policy denied\"" tests --include="*.cs"
```

For each match, replace the assertion. The new default reason from a sync-only policy returning `false` is **the same `"Policy denied"` reason** (the DIM bridge in ZeroAlloc.Authorization preserves it as the failure's `Reason`); the difference is the `Code` field is now `"policy_denied"` (or `AuthorizationFailure.DefaultDenyCode` — verify which by reading the package source if there's any uncertainty).

If the existing test only checks `Reason`, no change required. If it checks the full string format, add a `Code` assertion.

**Step 8: Verify the full suite stays green.**

```bash
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: `AI.Sentinel.Tests.dll` count = 588 (583 + 2 from Task 1.1 + 3 from Task 1.2). Other counts unchanged.

**Step 9: Commit.**

```bash
git add src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs tests/AI.Sentinel.Tests/Authorization/DefaultToolCallGuardTests.cs
git commit -m "feat(authz): switch DefaultToolCallGuard to policy.EvaluateAsync

EvaluatePolicy is now async and consumes UnitResult<AuthorizationFailure>
from ZeroAlloc.Authorization 1.1's structured EvaluateAsync API. The
policy-supplied Code (e.g. 'tenant_inactive') propagates to the
DenyDecision; cancellation is cooperative; any policy exception still
fails closed with code='policy_exception'; an unregistered policy denies
with code='policy_not_registered'.

Existing IsAuthorized-only policies (AdminOnlyPolicy, NoSystemPathsPolicy,
user-defined) keep working unchanged via the package's default-interface
-method bridges, surfacing as code='policy_denied'."
```

---

## Phase 2 — Audit propagation

### Task 2.1: Add `PolicyCode` to `AuditEntry`

**Files:**
- Modify: `src/AI.Sentinel/Audit/AuditEntry.cs`
- Test: `tests/AI.Sentinel.Tests/Audit/AuditEntryTests.cs` (or wherever existing AuditEntry tests live — grep first)

**Step 1: Locate AuditEntry.**

```bash
cat src/AI.Sentinel/Audit/AuditEntry.cs | head -40
```
Expected: a `record` type with positional parameters (`Id`, `Timestamp`, `Sender`, `Receiver`, `Session`, `DetectorId`, `Severity`, `Summary`, `Hash`, `PreviousHash`, ...).

**Step 2: Write the failing test.**

In whichever existing test file covers `AuditEntry`, append:

```csharp
[Fact]
public void AuditEntry_PolicyCode_DefaultsToNull()
{
    var entry = new AuditEntry(
        Id: "x", Timestamp: DateTimeOffset.UtcNow,
        Sender: new AgentId("a"), Receiver: new AgentId("b"), Session: SessionId.New(),
        DetectorId: "test", Severity: Severity.Low, Summary: "summary",
        Hash: "h", PreviousHash: null);
    Assert.Null(entry.PolicyCode);
}

[Fact]
public void AuditEntry_PolicyCode_PreservesValueWhenSet()
{
    var entry = new AuditEntry(
        Id: "x", Timestamp: DateTimeOffset.UtcNow,
        Sender: new AgentId("a"), Receiver: new AgentId("b"), Session: SessionId.New(),
        DetectorId: "AUTHZ-DENY", Severity: Severity.High, Summary: "summary",
        Hash: "h", PreviousHash: null,
        PolicyCode: "tenant_inactive");
    Assert.Equal("tenant_inactive", entry.PolicyCode);
}
```

**Step 3: Run — verify failure.** Build error: `'PolicyCode' is not a parameter of AuditEntry`.

**Step 4: Implement.**

Add `PolicyCode` as a positional record parameter with default `null`. Adjust the AuditEntry record signature; keep all existing parameters in place. Find the right slot — typically last, with default `null`:

Before:
```csharp
public sealed record AuditEntry(
    string Id, DateTimeOffset Timestamp,
    AgentId Sender, AgentId Receiver, SessionId Session,
    string DetectorId, Severity Severity, string Summary,
    string Hash, string? PreviousHash);
```

After:
```csharp
public sealed record AuditEntry(
    string Id, DateTimeOffset Timestamp,
    AgentId Sender, AgentId Receiver, SessionId Session,
    string DetectorId, Severity Severity, string Summary,
    string Hash, string? PreviousHash,
    string? PolicyCode = null);
```

**Step 5: Run — verify pass + full suite.**

```bash
dotnet build AI.Sentinel.slnx --nologo 2>&1 | tail -5
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: 0 errors, 0 warnings; main count = 590 (588 + 2 from this task).

**Step 6: Commit.**

```bash
git add src/AI.Sentinel/Audit/AuditEntry.cs tests/AI.Sentinel.Tests/Audit/AuditEntryTests.cs
git commit -m "feat(audit): add optional PolicyCode to AuditEntry

Additive — non-AUTHZ entries continue to omit the field (default null).
AUTHZ-DENY entries will populate it from the DenyDecision.Code in the
next task."
```

---

### Task 2.2: Plumb `policyCode` through `AuthorizationDeny` factory + 5 callers

**Files:**
- Modify: `src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs`
- Modify: `src/AI.Sentinel/Authorization/AuthorizationChatClient.cs:134`
- Modify: `src/AI.Sentinel.ClaudeCode/HookAdapter.cs:79,100`
- Modify: `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs:83,104`
- Modify: `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs:114`
- Test: `tests/AI.Sentinel.Tests/Audit/AuditEntryAuthorizationExtensionsTests.cs` (or equivalent)

**Step 1: Write the failing test.**

```csharp
[Fact]
public void AuthorizationDeny_PolicyCode_PersistsOnAuditEntry()
{
    var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
        sender: new AgentId("user"), receiver: new AgentId("agent"),
        session: SessionId.New(),
        callerId: "u1", roles: new HashSet<string>(StringComparer.Ordinal),
        toolName: "Bash", policyName: "TenantActive",
        reason: "Tenant 'acme' is in evicted state",
        policyCode: "tenant_inactive");
    Assert.Equal("tenant_inactive", entry.PolicyCode);
    Assert.Contains("tenant_inactive", entry.Summary, StringComparison.Ordinal);   // also surfaces in human-readable summary
}

[Fact]
public void AuthorizationDeny_DefaultsToPolicyDeniedWhenCodeOmitted()
{
    var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
        sender: new AgentId("user"), receiver: new AgentId("agent"),
        session: SessionId.New(),
        callerId: "u1", roles: new HashSet<string>(StringComparer.Ordinal),
        toolName: "Bash", policyName: "AdminOnly",
        reason: "Policy denied");   // policyCode parameter omitted
    Assert.Equal("policy_denied", entry.PolicyCode);
}
```

**Step 2: Run — verify failure.**

**Step 3: Implement extension method change.**

In `src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs`, add a `policyCode` parameter with default `"policy_denied"`. Update the summary template AND the entry constructor:

Before:
```csharp
public static AuditEntry AuthorizationDeny(
    AgentId sender, AgentId receiver, SessionId session,
    string callerId, IReadOnlySet<string> roles,
    string toolName, string policyName, string reason)
{
    ...
    var summary = string.Format(CultureInfo.InvariantCulture,
        "Caller '{0}' (roles: [{1}]) denied for tool '{2}' by policy '{3}' in session '{4}' ({5} -> {6}): {7}",
        callerId, ..., reason);
    return new AuditEntry(
        Id: ..., DetectorId: AuthorizationDenyDetectorId, ..., 
        Hash: ..., PreviousHash: null);
}
```

After:
```csharp
public static AuditEntry AuthorizationDeny(
    AgentId sender, AgentId receiver, SessionId session,
    string callerId, IReadOnlySet<string> roles,
    string toolName, string policyName, string reason,
    string policyCode = "policy_denied")
{
    ArgumentNullException.ThrowIfNull(sender);
    ArgumentNullException.ThrowIfNull(receiver);
    ArgumentNullException.ThrowIfNull(session);
    ArgumentNullException.ThrowIfNull(roles);

    var summary = string.Format(CultureInfo.InvariantCulture,
        "Caller '{0}' (roles: [{1}]) denied for tool '{2}' by policy '{3}' [{4}] in session '{5}' ({6} -> {7}): {8}",
        callerId, string.Join(",", roles), toolName, policyName, policyCode,
        session.Value, sender.Value, receiver.Value, reason);

    return new AuditEntry(
        Id:           Guid.NewGuid().ToString("N"),
        Timestamp:    DateTimeOffset.UtcNow,
        Sender:       sender,
        Receiver:     receiver,
        Session:      session,
        DetectorId:   AuthorizationDenyDetectorId,
        Severity:     Severity.High,
        Summary:      summary,
        Hash:         "",
        PreviousHash: null,
        PolicyCode:   policyCode);
}
```

**Step 4: Update the 5 call sites.**

For each call site, the deny decision is in scope as `decision` (or `deny`) — pass `decision.Code` (or `deny.Code`) as the new `policyCode` argument.

For example, in `src/AI.Sentinel/Authorization/AuthorizationChatClient.cs:134`:

Before:
```csharp
var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
    sender, receiver, session,
    caller.Id, caller.Roles,
    toolName: fnCall.Name,
    policyName: deny.PolicyName,
    reason: deny.Reason);
```

After:
```csharp
var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
    sender, receiver, session,
    caller.Id, caller.Roles,
    toolName: fnCall.Name,
    policyName: deny.PolicyName,
    reason: deny.Reason,
    policyCode: deny.Code);
```

Apply identical edits to:
- `src/AI.Sentinel.ClaudeCode/HookAdapter.cs:79,100`
- `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs:83,104`
- `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs:114`

For each: locate the `AuthorizationDeny(...)` call, find the `decision` variable in scope (look up a few lines), append `policyCode: decision.Code` to the named-argument list.

**Step 5: Run tests.**

```bash
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: 0 errors, 0 warnings; main count = 592 (590 + 2).

**Step 6: Commit.**

```bash
git add src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs \
        src/AI.Sentinel/Authorization/AuthorizationChatClient.cs \
        src/AI.Sentinel.ClaudeCode/HookAdapter.cs \
        src/AI.Sentinel.Copilot/CopilotHookAdapter.cs \
        src/AI.Sentinel.Mcp/ToolCallInterceptor.cs \
        tests/AI.Sentinel.Tests/Audit/
git commit -m "feat(audit): plumb policyCode through AuthorizationDeny extension

The summary string gains a [code] segment between the policy name and
session id; the AuditEntry.PolicyCode property carries the structured
code. All 5 callers (in-process middleware + 2 hook adapters + MCP
proxy) updated to pass the deny decision's Code through."
```

---

### Task 2.3: SqliteAuditStore schema migration (version 1 → 2)

**Files:**
- Modify: `src/AI.Sentinel.Sqlite/SqliteSchema.cs`
- Test: `tests/AI.Sentinel.Sqlite.Tests/SqliteSchemaTests.cs` (or `SqliteAuditStoreTests.cs`)

**Step 1: Read the existing schema.**

```bash
cat src/AI.Sentinel.Sqlite/SqliteSchema.cs
```

Confirm: current schema is at `PRAGMA user_version = 1` with the `audit_entries` table created in a single statement. The migration logic checks `user_version` and runs the upgrade SQL.

**Step 2: Write the failing test.**

In `tests/AI.Sentinel.Sqlite.Tests/SqliteSchemaTests.cs` (create file if absent):

```csharp
using Microsoft.Data.Sqlite;

public class SqliteSchemaMigrationTests
{
    [Fact]
    public async Task Migration_FromV1ToV2_AddsPolicyCodeColumnWithDefault()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"sqlite-mig-{Guid.NewGuid():N}.db");
        try
        {
            // Step 1: Create a fresh DB at v1 schema (manually emulate pre-1.6 state).
            await using (var conn = new SqliteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    CREATE TABLE audit_entries (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        sender TEXT, receiver TEXT, session TEXT,
                        detector_id TEXT, severity INTEGER, summary TEXT,
                        hash TEXT, previous_hash TEXT
                    );
                    INSERT INTO audit_entries(id, timestamp, sender, receiver, session, detector_id, severity, summary, hash, previous_hash)
                    VALUES ('legacy-1', '2026-04-30T00:00:00Z', 's', 'r', 'sess', 'AUTHZ-DENY', 4, 'old denial', 'h', NULL);
                    PRAGMA user_version = 1;
                    """;
                cmd.ExecuteNonQuery();
            }

            // Step 2: Run migration via SqliteSchema.Initialize (or whatever the public surface is).
            await using (var conn = new SqliteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                SqliteSchema.Initialize(conn);
            }

            // Step 3: Verify column exists, version bumped, legacy row backfilled.
            await using (var conn = new SqliteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                using var versionCmd = conn.CreateCommand();
                versionCmd.CommandText = "PRAGMA user_version;";
                Assert.Equal(2L, Convert.ToInt64(versionCmd.ExecuteScalar()));

                using var queryCmd = conn.CreateCommand();
                queryCmd.CommandText = "SELECT policy_code FROM audit_entries WHERE id='legacy-1';";
                Assert.Equal("policy_denied", (string)queryCmd.ExecuteScalar()!);
            }
        }
        finally
        {
            if (File.Exists(dbPath)) File.Delete(dbPath);
            foreach (var sidecar in new[] { dbPath + "-wal", dbPath + "-shm" })
                if (File.Exists(sidecar)) File.Delete(sidecar);
        }
    }
}
```

**Step 3: Run — verify failure.**

Expected: assertions fail (`user_version` is still 1; `policy_code` column doesn't exist).

**Step 4: Implement the migration.**

In `src/AI.Sentinel.Sqlite/SqliteSchema.cs`, after the existing v1 `CREATE TABLE` block, add a v1→v2 migration step:

```csharp
// existing — current state at version 1
if (currentVersion < 1) {
    using var createCmd = conn.CreateCommand();
    createCmd.CommandText = """
        CREATE TABLE IF NOT EXISTS audit_entries (...);
        PRAGMA user_version = 1;
        """;
    createCmd.ExecuteNonQuery();
}

// new — migrate to v2
if (currentVersion < 2) {
    using var migrateCmd = conn.CreateCommand();
    migrateCmd.CommandText = """
        ALTER TABLE audit_entries ADD COLUMN policy_code TEXT NOT NULL DEFAULT 'policy_denied';
        PRAGMA user_version = 2;
        """;
    migrateCmd.ExecuteNonQuery();
}
```

The `ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT ...` is non-locking on SQLite; existing rows retroactively read the default value.

If the v1 `CREATE TABLE` is for a fresh database, also update the v1 schema to include `policy_code TEXT NOT NULL DEFAULT 'policy_denied'` so new databases skip the migration. Two options:
- Option A: add the column to the v1 CREATE statement and bump initial `PRAGMA user_version = 2`. Cleaner — fresh DBs land at v2 directly.
- Option B: keep v1 unchanged, always run the v2 migration on fresh DBs too. Less ideal but simpler diff.

Recommend Option A. Adjust the test's pre-condition setup to match.

**Step 5: Run — verify migration test passes.**

```bash
dotnet test tests/AI.Sentinel.Sqlite.Tests/AI.Sentinel.Sqlite.Tests.csproj --nologo --filter "FullyQualifiedName~SqliteSchemaMigrationTests"
```

**Step 6: Commit.**

```bash
git add src/AI.Sentinel.Sqlite/SqliteSchema.cs tests/AI.Sentinel.Sqlite.Tests/
git commit -m "feat(sqlite): audit schema v2 — policy_code column

Migration: ALTER TABLE audit_entries ADD COLUMN policy_code TEXT NOT NULL
DEFAULT 'policy_denied'. Pre-1.6 audit DBs upgrade transparently on first
read; existing rows retroactively read the default value (faithful to
the old hardcoded reason). Fresh DBs land at v2 directly via the v1
CREATE statement update + initial PRAGMA user_version = 2."
```

---

### Task 2.4: SqliteAuditStore read/write code path

**Files:**
- Modify: `src/AI.Sentinel.Sqlite/SqliteAuditStore.cs` (the INSERT statement + the SELECT/projection in any query method)
- Test: existing `SqliteAuditStoreTests.cs` — add 1 round-trip test

**Step 1: Write the failing test.**

```csharp
[Fact]
public async Task RoundTrip_AuthorizationDenyWithCode_PreservesPolicyCode()
{
    var dbPath = Path.Combine(Path.GetTempPath(), $"audit-rt-{Guid.NewGuid():N}.db");
    try
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = dbPath });
        await store.InitializeAsync(default);

        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId("u"), receiver: new AgentId("a"), session: SessionId.New(),
            callerId: "u1", roles: new HashSet<string>(StringComparer.Ordinal),
            toolName: "Bash", policyName: "TenantActive",
            reason: "Tenant evicted",
            policyCode: "tenant_inactive");
        await store.AppendAsync(entry, default);

        var entries = await store.QueryAsync(default).ToListAsync();
        Assert.Single(entries);
        Assert.Equal("tenant_inactive", entries[0].PolicyCode);
    }
    finally
    {
        foreach (var path in new[] { dbPath, dbPath + "-wal", dbPath + "-shm" })
            if (File.Exists(path)) File.Delete(path);
    }
}
```

(Adapt the API signature to the actual `SqliteAuditStore` query / append surface — read the existing tests to match.)

**Step 2: Run — verify failure** (column not in INSERT/SELECT).

**Step 3: Implement.**

In `src/AI.Sentinel.Sqlite/SqliteAuditStore.cs`:
- INSERT statement gains `policy_code` column + `$policy_code` parameter; bind from `entry.PolicyCode ?? "policy_denied"`.
- SELECT statement gains `policy_code`; project into `AuditEntry.PolicyCode` on the row reader.

Read the existing INSERT/SELECT to find the exact pattern. Add `policy_code` consistently in both directions.

**Step 4: Run — verify pass + full suite.**

Expected: main count unchanged; Sqlite count = 11 (10 + 1).

**Step 5: Commit.**

```bash
git add src/AI.Sentinel.Sqlite/SqliteAuditStore.cs tests/AI.Sentinel.Sqlite.Tests/
git commit -m "feat(sqlite): persist + read AuditEntry.PolicyCode

INSERT binds entry.PolicyCode (defaulting to 'policy_denied' for legacy
non-AUTHZ entries); SELECT projects policy_code into AuditEntry.PolicyCode."
```

---

### Task 2.5: NDJSON / AzureSentinel / OpenTelemetry forwarder DTOs

**Files:**
- Modify: each forwarder's per-row JSON DTO + corresponding `JsonSerializerContext` (look for `[JsonSerializable(typeof(...))]` attributes)
- Tests: existing forwarder tests — update snapshot assertions to expect the `"policyCode"` field

**Step 1: Locate the forwarders.**

```bash
grep -rln "AuditEntry\b" src/AI.Sentinel.OpenTelemetry src/AI.Sentinel.AzureSentinel src/AI.Sentinel --include="*.cs" | grep -i "forward\|ndjson\|writer"
```

Target files:
- `src/AI.Sentinel/Audit/NdjsonFileAuditForwarder.cs` (or similar)
- `src/AI.Sentinel.AzureSentinel/AzureSentinelAuditForwarder.cs`
- `src/AI.Sentinel.OpenTelemetry/OpenTelemetryAuditForwarder.cs`

For each: find the DTO that gets serialized. Some may serialize `AuditEntry` directly (no DTO change needed — `PolicyCode` flows through automatically via `JsonInclude`); others may use a per-forwarder shape DTO.

**Step 2: For each forwarder using a DTO, add `PolicyCode` (json name `policyCode`).**

Per-forwarder DTO change pattern:

```csharp
// before:
internal sealed record AuditEntryDto(string Id, ..., string Reason);

// after:
internal sealed record AuditEntryDto(string Id, ..., string Reason, string? PolicyCode = null);
```

**Step 3: Update JSON snapshot assertions in tests.**

```bash
grep -rn '"reason"' tests --include="*.cs" | grep -i "forward\|ndjson"
```

For each match, add an assertion that the serialized JSON now contains `"policyCode"` when the source entry has one.

**Step 4: Verify build + tests.**

```bash
dotnet build AI.Sentinel.slnx --nologo 2>&1 | tail -5
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: counts unchanged or +1-2 if you added new tests.

**Step 5: Commit.**

```bash
git add src/AI.Sentinel/Audit/ src/AI.Sentinel.AzureSentinel/ src/AI.Sentinel.OpenTelemetry/ tests/
git commit -m "feat(audit): propagate policyCode through audit forwarders

NdjsonFileAuditForwarder, AzureSentinelAuditForwarder, and
OpenTelemetryAuditForwarder all serialize AuditEntry.PolicyCode as
'policyCode' in their per-row JSON. JsonSerializerContext source-gen
tables regenerate from the updated DTOs."
```

---

## Phase 3 — CLI receipts

### Task 3.1: `sentinel-hook` stderr receipt format

**Files:**
- Modify: `src/AI.Sentinel.ClaudeCode.Cli/Program.cs` (or wherever the AUTHZ deny stderr message is formatted — grep for `"Denied:"`)
- Tests: `tests/AI.Sentinel.Tests/ClaudeCode/HookCliTests.cs`

**Step 1: Locate the receipt format.**

```bash
grep -rn "Denied:" src/AI.Sentinel.ClaudeCode src/AI.Sentinel.ClaudeCode.Cli --include="*.cs"
```

**Step 2: Update existing receipt tests + add a new one.**

Existing tests asserting against `"Denied:"` need updating to `"Authorization denied ["`. Add one new test:

```csharp
[Fact]
public async Task Cli_AuthzDeny_ReceiptIncludesPolicyCode()
{
    // Configure SENTINEL_APPROVAL_CONFIG with a policy that denies with a structured code.
    // Or — simpler — wire a fake IToolCallGuard that returns a Deny with code='tenant_inactive'.
    var stdin = new StringReader("""{"session_id":"s","prompt":"hello","tool_name":"Bash"}""");
    var stdout = new StringWriter();
    var stderr = new StringWriter();
    
    var exit = await Program.RunAsync(["pre-tool-use"], stdin, stdout, stderr,
        // ... override services to inject a Deny('tenant_inactive') decision
    );
    
    Assert.Equal(2, exit);
    Assert.Contains("[tenant_inactive]", stderr.ToString(), StringComparison.Ordinal);
}
```

(Adapt to the real Cli surface — the ConsoleDemo `/approve-demo` pattern is a good reference.)

**Step 3: Implement the format change.**

Find the format string. Before:
```csharp
await stderr.WriteAsync($"Denied: {reason}").ConfigureAwait(false);
```

After:
```csharp
await stderr.WriteAsync($"Authorization denied [{code}]: {reason}").ConfigureAwait(false);
```

Where `code` is sourced from `decision.Code` if `decision is DenyDecision deny`.

**Step 4: Run — verify pass + full suite.**

**Step 5: Commit.**

```bash
git add src/AI.Sentinel.ClaudeCode.Cli/ src/AI.Sentinel.ClaudeCode/ tests/AI.Sentinel.Tests/ClaudeCode/
git commit -m "feat(claudecode-cli): include policyCode in deny-with-receipt

Stderr receipt format becomes 'Authorization denied [code]: reason' to
surface the policy-supplied code alongside the reason. Operators can
correlate receipt output with audit-log queries for the same code."
```

---

### Task 3.2: `sentinel-copilot-hook` stderr receipt format

Same pattern as Task 3.1 applied to:
- `src/AI.Sentinel.Copilot.Cli/Program.cs` (or `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs`)
- `tests/AI.Sentinel.Tests/Copilot/CopilotHookCliTests.cs`

Commit:
```bash
git commit -m "feat(copilot-cli): include policyCode in deny-with-receipt"
```

---

### Task 3.3: `sentinel-mcp` JSON-RPC error body — `data.policyCode`

**Files:**
- Modify: `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs` (or wherever the JSON-RPC error envelope is built)
- Tests: `tests/AI.Sentinel.Tests/Mcp/AuthorizationTests.cs` or similar

**Step 1: Locate the error builder.**

```bash
grep -rn "policyName\|approvalRequired\|jsonrpc" src/AI.Sentinel.Mcp --include="*.cs" | grep -i "error\|data"
```

**Step 2: Write the failing test.**

```csharp
[Fact]
public async Task McpProxy_ToolCallDenied_ErrorDataContainsPolicyCode()
{
    // Configure a guard that returns Deny('tenant_inactive') for tool 'Bash'.
    // Drive a JSON-RPC tools/call request through the proxy.
    // Capture the error response.
    var responseJson = ...;   // captured proxy response

    var error = JsonDocument.Parse(responseJson).RootElement.GetProperty("error");
    Assert.Equal(-32000, error.GetProperty("code").GetInt32());
    var data = error.GetProperty("data");
    Assert.Equal("tenant_inactive", data.GetProperty("policyCode").GetString());
    Assert.Equal("TenantActive", data.GetProperty("policyName").GetString());
}
```

**Step 3: Implement.**

Find the JSON-RPC error builder. The error.data object today probably has `policyName`, `reason`, `approvalRequired`. Add `policyCode` (sourced from `decision.Code` when `decision is DenyDecision`):

```csharp
data: new {
    policyName = deny.PolicyName,
    policyCode = deny.Code,
    reason = deny.Reason,
    approvalRequired = false,
}
```

If the project uses source-gen JSON, update the corresponding `JsonSerializerContext` to include the new field type.

**Step 4: Verify + commit.**

```bash
git add src/AI.Sentinel.Mcp/ src/AI.Sentinel.Mcp.Cli/ tests/
git commit -m "feat(mcp-cli): add policyCode to JSON-RPC error.data envelope

Top-level error.code stays the JSON-RPC reserved -32000; the data
payload gains policyCode alongside the existing policyName / reason /
approvalRequired fields. Purely additive — clients ignoring the new
field keep working."
```

---

## Phase 4 — Dashboard UI

### Task 4.1: Render `<span class="badge code">code</span>` prefix on AUTHZ-DENY rows

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs` (the live-feed AUTHZ-DENY row template)
- Test: `tests/AI.Sentinel.Tests/AspNetCore/DashboardFeedTests.cs` (or wherever live-feed snapshot tests live)

**Step 1: Locate the live-feed AUTHZ row template.**

```bash
grep -rn "audit-row-authz" src/AI.Sentinel.AspNetCore --include="*.cs"
```

Find the function that builds the `<tr class="audit-row-authz">` and the `<td>` that renders Reason.

**Step 2: Update the template.**

Before:
```csharp
sb.Append("<td>").Append(htmlEncodedReason).Append("</td>");
```

After:
```csharp
sb.Append("<td><span class=\"badge code\">")
  .Append(HtmlEncoder.Default.Encode(entry.PolicyCode ?? "policy_denied"))
  .Append("</span> ")
  .Append(htmlEncodedReason)
  .Append("</td>");
```

**Step 3: Update / add the snapshot test.**

```csharp
[Fact]
public async Task LiveFeed_AuthzDenyRow_RendersBadgeCodePrefix()
{
    var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
        sender: new AgentId("u"), receiver: new AgentId("a"), session: SessionId.New(),
        callerId: "u1", roles: new HashSet<string>(StringComparer.Ordinal),
        toolName: "Bash", policyName: "TenantActive",
        reason: "Tenant evicted", policyCode: "tenant_inactive");

    var html = await RenderFeedAsync([entry]);   // or however the existing snapshot tests render
    Assert.Contains("<span class=\"badge code\">tenant_inactive</span>", html, StringComparison.Ordinal);
}
```

**Step 4: Verify + commit.**

```bash
git add src/AI.Sentinel.AspNetCore/DashboardHandlers.cs tests/AI.Sentinel.Tests/AspNetCore/
git commit -m "feat(dashboard): render policyCode as inline badge on AUTHZ-DENY rows

The live-feed Reason cell becomes '<span class=\"badge code\">code</span> reason'
for AUTHZ-DENY entries. Existing tr.audit-row-authz styling untouched;
mobile breakpoint behavior unchanged."
```

---

### Task 4.2: Add `.badge.code` CSS rule

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/wwwroot/sentinel.css`

**Step 1: Append the rule.**

In `src/AI.Sentinel.AspNetCore/wwwroot/sentinel.css`, after the existing `.badge` rules:

```css
/* Inline machine-readable policy code on AUTHZ-DENY rows.
   Tucks at the head of the Reason cell — no new column. */
.badge.code {
    display: inline-block;
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
    font-size: 0.85em;
    padding: 0.05em 0.4em;
    margin-right: 0.4em;
    background: rgba(255, 255, 255, 0.06);
    color: var(--text-muted);
    border-radius: 3px;
}
```

**Step 2: Commit.**

```bash
git add src/AI.Sentinel.AspNetCore/wwwroot/sentinel.css
git commit -m "feat(dashboard): .badge.code CSS rule for inline policyCode badges

Mono font, muted background, smaller font-size. Fits the existing
.badge family without a new column or breakpoint change."
```

---

### Task 4.3: Regression-test the rendered HTML end-to-end

**Files:**
- Test: existing `DashboardApprovalsTests.cs` or similar — add an integration test that drives a full HTTP request and verifies the badge HTML appears in the response body

**Step 1: Pattern-match an existing dashboard integration test.**

```bash
grep -rn "TestServer\|WebApplicationFactory" tests --include="*.cs" | head -5
```

Use the same pattern. Add:

```csharp
[Fact]
public async Task LiveFeedEndpoint_AuthzDenyEntry_RendersBadgeInResponseBody()
{
    using var host = await CreateTestHostAsync(seedAuditEntry: AuditEntryAuthorizationExtensions.AuthorizationDeny(
        sender: new AgentId("u"), receiver: new AgentId("a"), session: SessionId.New(),
        callerId: "u1", roles: new HashSet<string>(StringComparer.Ordinal),
        toolName: "Bash", policyName: "TenantActive",
        reason: "Tenant evicted", policyCode: "tenant_inactive"));
    var client = host.GetTestClient();
    var resp = await client.GetAsync("/ai-sentinel/api/feed");
    var html = await resp.Content.ReadAsStringAsync();
    Assert.Contains("<span class=\"badge code\">tenant_inactive</span>", html, StringComparison.Ordinal);
}
```

**Step 2: Verify + commit.**

```bash
git add tests/AI.Sentinel.Tests/AspNetCore/
git commit -m "test(dashboard): integration test for badge HTML in live feed"
```

---

## Phase 5 — Final + PR

### Task 5.1: Full suite + AOT publish probe

**Step 1: Final test count check.**

```bash
dotnet test AI.Sentinel.slnx --nologo 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: `AI.Sentinel.Tests.dll` ≈ 595 (583 + ~12), `AI.Sentinel.Sqlite.Tests.dll` = 11, others unchanged. Total ≈ **680**.

**Step 2: AOT publish probe** (one CLI is enough — the pattern is identical across all three).

```bash
dotnet publish src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj -c Release -r win-x64 -p:PublishAot=true -o /tmp/aot-probe-1.6 2>&1 | grep -E "warning IL|error IL"
```
Expected: zero IL warnings. Type-forwarders + the new EvaluateAsync call should not introduce any.

If the local toolchain can't run native linking, that's fine — the IL warning check is what matters; CI handles native linking.

---

### Task 5.2: Push branch + open PR

```bash
git push -u origin feat/async-structured-authorization
gh pr create --base main --head feat/async-structured-authorization \
  --title "feat(authz): async + structured authorization (Code propagation end-to-end)" \
  --body "$(cat <<'EOF'
## Summary

Switches \`DefaultToolCallGuard\` from synchronous \`policy.IsAuthorized(ctx)\` to asynchronous structured \`policy.EvaluateAsync(ctx, ct)\`, then surfaces the policy-supplied \`Code\` end-to-end through:
- \`DenyDecision.Code\` (additive, default \`"policy_denied"\`)
- \`AuditEntry.PolicyCode\` (additive, default \`null\`)
- \`SqliteAuditStore\` schema v2 (\`ALTER TABLE ... ADD COLUMN policy_code TEXT NOT NULL DEFAULT 'policy_denied'\`)
- NDJSON / Azure Sentinel / OpenTelemetry forwarder JSON DTOs (\`"policyCode"\` field)
- \`sentinel-hook\` + \`sentinel-copilot-hook\` stderr receipts (\`Authorization denied [code]: reason\`)
- \`sentinel-mcp\` JSON-RPC \`error.message\` carries the \`[code]\` token (\`McpProtocolException\` has no \`data\`-bearing constructor in ModelContextProtocol 1.2.0; see Phase 3 retro)
- Dashboard live-feed AUTHZ-DENY rows (inline \`<span class="badge code">\` prefix)

Strictly additive — existing \`IsAuthorized\`-only policies (AdminOnlyPolicy, NoSystemPathsPolicy, user-defined) keep working unchanged via ZeroAlloc.Authorization 1.1's default-interface-method bridges, surfacing as \`code='policy_denied'\`.

## Design + Plan

- Design: [\`docs/plans/2026-05-01-async-structured-authorization-design.md\`](docs/plans/2026-05-01-async-structured-authorization-design.md)
- Plan: [\`docs/plans/2026-05-01-async-structured-authorization.md\`](docs/plans/2026-05-01-async-structured-authorization.md)

## Test plan

- [x] Full \`dotnet test AI.Sentinel.slnx\` green (~680 tests across net8 + net10; baseline was 668)
- [x] SQLite migration test — pre-1.6 audit DB upgrades cleanly (\`policy_code\` backfilled to \`'policy_denied'\`)
- [x] \`dotnet build samples/ConsoleDemo/ConsoleDemo.csproj\` green
- [ ] AOT publish CI matrix green for all three CLIs
- [ ] After merge, release-please opens 1.6.0 PR with the \`feat:\` commits in the changelog

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Final review checklist

- [ ] All 5 callers of `AuthorizationDeny` pass `decision.Code` through (in-process middleware + 2 hook adapters + MCP proxy + the catch-all dashboard panel if it routes through the same factory)
- [ ] All 3 forwarders serialize `policyCode` (NDJSON, Azure Sentinel, OpenTelemetry)
- [ ] Sqlite migration test exercises both fresh-DB and v1→v2-upgrade paths
- [ ] Hook receipt tests assert against the new format string
- [x] MCP error body test verifies `[<code>]` token surfaces in `error.message` (no `data.policyCode` — SDK constraint, see Phase 3 retro)
- [ ] Dashboard integration test verifies the badge HTML in the response body
- [ ] No positional `case DenyDecision(...)` patterns introduced anywhere
- [ ] AOT publish probe clean (0 IL warnings)
- [ ] Full test count: ~680

---

## Out of scope (deferred follow-ups)

- `opts.PolicyTimeout` — separate backlog item.
- Source-gen-driven policy-name lookup — separate backlog item.
- `opts.AuditAllows` — different feature.
- Code-fix analyzer that nudges sync-only policy authors toward `Evaluate` overrides — defer until a real customer has a structured-code use case.

---

## Phase 3 retro (post-implementation)

Three plan-vs-reality drifts surfaced during Phase 3 implementation; documenting here so future readers don't re-discover them:

1. **MCP `error.data.policyCode` not implemented — `error.message` carries the code instead.** ModelContextProtocol 1.2.0 exposes only `McpProtocolException(string message, McpErrorCode code)` constructors; `JsonRpcErrorDetail.Data` exists in the SDK as an inbound-deserialization DTO but no application hook lets the proxy populate `Data` on outbound errors. The plan envisioned a structured `error.data: { policyName, policyCode, reason, approvalRequired }` field but that wire format is unreachable from this SDK. Implementation embeds `[<code>]` directly in `error.message`, which is the only available channel. Operators parsing the wire format extract the code via `\[([a-z_]+)\]`.

2. **Receipt format kept the existing `by policy '<name>'` segment.** Plan example showed `Authorization denied [code]: reason`; final format is `Authorization denied [code] by policy '<name>': reason`. This preserves the prior format's `by policy '<name>'` token so existing operator scripts and existing test assertions (`Assert.Contains("admin-only", ...)`) keep working unchanged. Mild trade-off: extracting just the code from the receipt now needs a regex (`\[[^\]]+\]`) rather than anchoring on `denied [` → `]:`.

3. **MCP error code stays `McpErrorCode.InvalidRequest`** rather than `-32000`/InternalError as the plan suggested. The codebase chose `InvalidRequest` historically; preserving that choice avoids a breaking change for downstream MCP clients that key on the error code.

4. **Dashboard `.badge.code` overrides the parent `.badge` rule's `text-transform: uppercase`** so codes render as their canonical lowercase snake_case form (e.g. `tenant_inactive`, not `TENANT_INACTIVE`). The wire format is the same everywhere — audit log, JSON, MCP error message, hook receipt — and the dashboard should match what operators grep their logs for. Final-review code-quality reviewer flagged the inheritance as a Minor inconsistency; fix is `text-transform: none; letter-spacing: 0;` on `.badge.code`.

5. **`AuthorizationDecision.AsBinary()` propagates `code='approval_required'`** when folding a `RequireApprovalDecision` into a binary deny, matching what the production audit-write paths use for the same scenario. Without this, the folded pseudo-deny would default to `policy_denied`, conflating an approval-required state with a real policy denial in any consumer that calls `AsBinary()` (currently only test code, but defensive).

## Out of scope (carried as 1.7.0 follow-ups)

- **Dashboard badge gating.** Today the dashboard renders the badge on every `DetectorId.StartsWith("AUTHZ-")` row. When future detectors like `AUTHZ-AUDIT` or `AUTHZ-WARN` land, those rows will fall back to `policy_denied` (semantically wrong — an audit row is not a denial). Tighten to either `DetectorId == "AUTHZ-DENY"` exact-match OR detector-aware fallback string when the AUTHZ-* taxonomy expands.
- **Centralize the deny-code vocabulary.** The five canonical codes (`policy_denied`, `policy_not_registered`, `policy_exception`, `approval_required`, `approval_store_exception`, `approval_state_unknown`) appear as raw string literals across 6+ files. A `public static class SentinelDenyCodes` with `public const string PolicyDenied = "policy_denied";` etc. would centralize the vocabulary and let consumers `switch` on stable references. Pure additive cleanup; defer.
- **MCP `error.data.policyCode` once the SDK exposes a `data`-bearing constructor.** Track `ModelContextProtocol` upstream — when `McpProtocolException` gains a `data` overload, switch from message-embedded `[code]` to structured `error.data.policyCode`.

---

## Versioning

**AI.Sentinel 1.6.0** — minor bump. All changes additive: `Code` defaults preserve call sites; audit schema migration is non-destructive; receipt format and JSON-RPC error body are operator-facing wobbles, not API contracts. release-please opens the 1.6.0 PR automatically when this PR merges and it sees the `feat:` commits.
