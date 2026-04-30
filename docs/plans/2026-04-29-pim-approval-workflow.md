# PIM-Style Approval Workflow Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `RequireApproval` decision tier to `IToolCallGuard` plus a pluggable `IApprovalStore` abstraction with three backends (InMemory, Sqlite, Entra PIM), so high-stakes tool calls (`delete_database`, `send_payment`) can be gated behind out-of-band human approval.

**Architecture:** Sealed `AuthorizationDecision` hierarchy with three records (Allow/Deny/RequireApproval). New `IApprovalStore` + optional `IApprovalAdmin` interfaces in core. Three concrete stores in three packages (core for InMemory, two new packages for Sqlite + EntraPim). CLI hooks emit deny-with-receipt for stateless flows; middleware blocks-and-waits via `WaitForDecisionAsync`.

**Tech Stack:** .NET 8/9/10, xUnit, Microsoft.Data.Sqlite, Azure.Identity (`ChainedTokenCredential`), Microsoft Graph SDK v5, HTMX/SSE for dashboard.

**Reference:** Full design doc lives at [docs/plans/2026-04-29-pim-approval-workflow-design.md](2026-04-29-pim-approval-workflow-design.md). All API shapes, types, payloads, and configuration formats are normative there — this plan is the *executable* shape.

---

## Stage 1 — Core abstraction + InMemoryApprovalStore + middleware integration

### Task 1.1: Migrate `AuthorizationDecision` to a sealed hierarchy

**Why first:** the existing `AuthorizationDecision` is a flat record with `bool Allowed`. The design needs a sealed hierarchy. Convert in one breaking commit before adding the third tier — keeps the diff readable and the migration testable.

**Files:**
- Modify: `src/AI.Sentinel/Authorization/AuthorizationDecision.cs`
- Modify: `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`
- Modify: `src/AI.Sentinel/Authorization/IToolCallGuard.cs` (no change to signature, but XML doc updates)
- Modify: `tests/AI.Sentinel.Tests/Authorization/SentinelOptionsAuthorizationTests.cs`
- Modify: `tests/AI.Sentinel.Tests/Mcp/AuthorizationTests.cs`

**Step 1: Replace the flat record with sealed hierarchy.**

Open `src/AI.Sentinel/Authorization/AuthorizationDecision.cs` and replace contents:

```csharp
namespace AI.Sentinel.Authorization;

/// <summary>Result of a tool-call authorization check.</summary>
public abstract record AuthorizationDecision
{
    /// <summary>The call is permitted. Singleton instance to avoid allocation.</summary>
    public sealed record AllowDecision : AuthorizationDecision;

    /// <summary>The call is refused.</summary>
    public sealed record DenyDecision(string PolicyName, string Reason) : AuthorizationDecision;

    /// <summary>Singleton allow.</summary>
    public static readonly AllowDecision Allow = new();

    /// <summary>Builds a deny decision.</summary>
    public static DenyDecision Deny(string policyName, string reason) =>
        new(policyName, reason);

    /// <summary>True if this decision permits the call.</summary>
    public bool Allowed => this is AllowDecision;
}
```

The `Allowed` shim and the static `Allow` / `Deny(...)` factories preserve the v1 source contract so existing `decision.Allowed` and `decision == Decision.Allow` patterns keep working.

**Step 2: Update `DefaultToolCallGuard` switch sites (4 sites).**

In `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`, the existing calls already use the static factories — should compile unchanged after Step 1. Run `dotnet build src/AI.Sentinel` to confirm.

**Step 3: Update tests.**

`tests/AI.Sentinel.Tests/Authorization/SentinelOptionsAuthorizationTests.cs:38` already calls `AuthorizationDecision.Deny(...)` — should still work. Run the auth tests:

```
dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~Authorization" --nologo -v minimal
```

Expected: PASS.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel/Authorization/AuthorizationDecision.cs
git commit -m "refactor(authz): convert AuthorizationDecision to sealed hierarchy

Preserves the v1 source contract (Allowed shim + static Allow/Deny
factories) so existing consumers compile unchanged. Sets up the
shape for Task 1.2 — adding RequireApproval as a third sealed record."
```

---

### Task 1.2: Add the `RequireApprovalDecision` tier

**Files:**
- Modify: `src/AI.Sentinel/Authorization/AuthorizationDecision.cs`
- Test: `tests/AI.Sentinel.Tests/Authorization/AuthorizationDecisionTests.cs` (new)

**Step 1: Write the failing test.**

Create `tests/AI.Sentinel.Tests/Authorization/AuthorizationDecisionTests.cs`:

```csharp
using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class AuthorizationDecisionTests
{
    [Fact]
    public void RequireApproval_Allowed_IsFalse()
    {
        var d = AuthorizationDecision.RequireApproval(
            policyName: "AdminApproval",
            requestId: "req-123",
            approvalUrl: "https://example.test/approve/req-123",
            requestedAt: DateTimeOffset.UtcNow);

        Assert.False(d.Allowed);
        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
    }

    [Fact]
    public void Allow_Allowed_IsTrue() =>
        Assert.True(AuthorizationDecision.Allow.Allowed);

    [Fact]
    public void Deny_Allowed_IsFalse() =>
        Assert.False(AuthorizationDecision.Deny("p", "r").Allowed);

    [Fact]
    public void AsBinary_RequireApproval_BecomesDeny()
    {
        var pending = AuthorizationDecision.RequireApproval("AdminApproval", "req-1", "url", DateTimeOffset.UtcNow);

        var binary = pending.AsBinary();

        Assert.IsType<AuthorizationDecision.DenyDecision>(binary);
    }
}
```

**Step 2: Run — expect FAIL.**

```
dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~AuthorizationDecisionTests"
```
Expected: compile error — `RequireApprovalDecision`, `RequireApproval(...)`, `AsBinary()` don't exist.

**Step 3: Implement.**

Append to `src/AI.Sentinel/Authorization/AuthorizationDecision.cs` inside the `AuthorizationDecision` body:

```csharp
public sealed record RequireApprovalDecision(
    string PolicyName,
    string RequestId,
    string ApprovalUrl,
    DateTimeOffset RequestedAt) : AuthorizationDecision;

public static RequireApprovalDecision RequireApproval(
    string policyName, string requestId, string approvalUrl, DateTimeOffset requestedAt) =>
    new(policyName, requestId, approvalUrl, requestedAt);

/// <summary>
/// Folds a <see cref="RequireApprovalDecision"/> into a <see cref="DenyDecision"/> for callers
/// that don't participate in the approval flow (CS8509 dodge).
/// </summary>
public AuthorizationDecision AsBinary() =>
    this is RequireApprovalDecision r
        ? Deny(r.PolicyName, $"approval required (requestId={r.RequestId})")
        : this;
```

**Step 4: Run — expect PASS.**

```
dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~AuthorizationDecisionTests"
```

**Step 5: Commit.**

```bash
git add src/AI.Sentinel/Authorization/AuthorizationDecision.cs tests/AI.Sentinel.Tests/Authorization/AuthorizationDecisionTests.cs
git commit -m "feat(authz): RequireApproval decision tier + AsBinary fold helper"
```

---

### Task 1.3: `ApprovalSpec` + `ApprovalContext` + `PendingRequest` records

**Files:**
- Create: `src/AI.Sentinel/Approvals/ApprovalSpec.cs`
- Create: `src/AI.Sentinel/Approvals/ApprovalContext.cs`
- Create: `src/AI.Sentinel/Approvals/PendingRequest.cs`

**Step 1: Create the supporting types** (no tests — these are POCO records exercised through the store tests in Task 1.5).

`src/AI.Sentinel/Approvals/ApprovalSpec.cs`:

```csharp
namespace AI.Sentinel.Approvals;

/// <summary>
/// Configuration for an approval-required tool binding. Read by <see cref="IApprovalStore"/>
/// implementations to decide grant duration, justification policy, and backend-specific
/// bindings (e.g., PIM role name).
/// </summary>
public sealed class ApprovalSpec
{
    /// <summary>The policy name the approval gate is bound to. Used as the dedupe key
    /// alongside the caller identity.</summary>
    public required string PolicyName { get; init; }

    /// <summary>How long an approved grant remains active before re-approval is needed.</summary>
    public TimeSpan GrantDuration { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Whether a justification string must be provided at request time.</summary>
    public bool RequireJustification { get; init; } = true;

    /// <summary>Maximum time a host that block-and-waits will tolerate before timing out.</summary>
    public TimeSpan WaitTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Backend-specific identifier (PIM role name for EntraPim, ignored otherwise).</summary>
    public string? BackendBinding { get; init; }
}
```

`src/AI.Sentinel/Approvals/ApprovalContext.cs`:

```csharp
using System.Text.Json;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Per-request context surfaced to the approver: the tool being invoked, its arguments,
/// and an optional justification string sourced from the agent's reasoning context.
/// </summary>
public sealed record ApprovalContext(
    string ToolName,
    JsonElement Args,
    string? Justification);
```

`src/AI.Sentinel/Approvals/PendingRequest.cs`:

```csharp
using System.Text.Json;

namespace AI.Sentinel.Approvals;

/// <summary>A pending approval request as exposed by <see cref="IApprovalAdmin.ListPendingAsync"/>.</summary>
public sealed record PendingRequest(
    string RequestId,
    string CallerId,
    string PolicyName,
    string ToolName,
    JsonElement Args,
    DateTimeOffset RequestedAt,
    string? Justification);
```

**Step 2: Build.**

```
dotnet build src/AI.Sentinel
```

**Step 3: Commit.**

```bash
git add src/AI.Sentinel/Approvals/
git commit -m "feat(approvals): ApprovalSpec / ApprovalContext / PendingRequest records"
```

---

### Task 1.4: `ApprovalState` sealed hierarchy + `IApprovalStore` + `IApprovalAdmin` interfaces

**Files:**
- Create: `src/AI.Sentinel/Approvals/ApprovalState.cs`
- Create: `src/AI.Sentinel/Approvals/IApprovalStore.cs`
- Create: `src/AI.Sentinel/Approvals/IApprovalAdmin.cs`

**Step 1: Create `ApprovalState`.**

```csharp
namespace AI.Sentinel.Approvals;

/// <summary>The state of an approval request. <see cref="IApprovalStore.EnsureRequestAsync"/>
/// always returns one of the three concrete subclasses.</summary>
public abstract record ApprovalState
{
    /// <summary>An approval is currently active. The grant expires at <paramref name="ExpiresAt"/>.</summary>
    public sealed record Active(DateTimeOffset ExpiresAt) : ApprovalState;

    /// <summary>An approval is pending. The caller should wait or fail-with-receipt.</summary>
    public sealed record Pending(string RequestId, string ApprovalUrl, DateTimeOffset RequestedAt) : ApprovalState;

    /// <summary>The approval was denied or has expired.</summary>
    public sealed record Denied(string Reason, DateTimeOffset DeniedAt) : ApprovalState;
}
```

**Step 2: Create `IApprovalStore`.**

```csharp
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Pluggable approval backend. Implementations: <see cref="InMemoryApprovalStore"/> in core,
/// <c>SqliteApprovalStore</c> in <c>AI.Sentinel.Approvals.Sqlite</c>, <c>EntraPimApprovalStore</c>
/// in <c>AI.Sentinel.Approvals.EntraPim</c>.
/// </summary>
public interface IApprovalStore
{
    /// <summary>
    /// Returns the current state for <c>(caller, spec.PolicyName)</c>. Idempotent: repeated calls
    /// during a pending or active grant return the same state without creating duplicate requests.
    /// </summary>
    ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller,
        ApprovalSpec spec,
        ApprovalContext context,
        CancellationToken ct);

    /// <summary>
    /// Blocks until the named request transitions to <see cref="ApprovalState.Active"/> or
    /// <see cref="ApprovalState.Denied"/>, or the timeout elapses (returns the most recent state).
    /// </summary>
    ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId,
        TimeSpan timeout,
        CancellationToken ct);
}
```

**Step 3: Create `IApprovalAdmin`.**

```csharp
namespace AI.Sentinel.Approvals;

/// <summary>
/// Admin surface for stores that own approval state (InMemory, Sqlite). EntraPim does NOT
/// implement this — approvals happen in the PIM portal. Dashboard checks
/// <c>store is IApprovalAdmin</c> to decide whether to render Approve/Deny buttons.
/// </summary>
public interface IApprovalAdmin
{
    ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct);
    ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct);
    IAsyncEnumerable<PendingRequest> ListPendingAsync(CancellationToken ct);
}
```

**Step 4: Build + commit.**

```
dotnet build src/AI.Sentinel
git add src/AI.Sentinel/Approvals/
git commit -m "feat(approvals): IApprovalStore + IApprovalAdmin contracts + ApprovalState"
```

---

### Task 1.5: `InMemoryApprovalStore` — first concrete

**Files:**
- Create: `src/AI.Sentinel/Approvals/InMemoryApprovalStore.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/InMemoryApprovalStoreTests.cs` (new)

**Step 1: Write failing tests** that pin the contract:

```csharp
using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using System.Text.Json;
using Xunit;

namespace AI.Sentinel.Tests.Approvals;

public class InMemoryApprovalStoreTests
{
    private static ApprovalSpec MakeSpec(string policy = "p", TimeSpan? grant = null) =>
        new() { PolicyName = policy, GrantDuration = grant ?? TimeSpan.FromMinutes(15) };
    private static ApprovalContext MakeCtx() => new("delete_database", default, null);
    private static ISecurityContext MakeCaller(string id = "alice") =>
        new TestSecurityContext(id);
    private sealed record TestSecurityContext(string Id) : ISecurityContext { public IReadOnlyList<string> Roles => Array.Empty<string>(); }

    [Fact]
    public async Task EnsureRequest_FirstCall_ReturnsPending()
    {
        var store = new InMemoryApprovalStore();
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Pending>(state);
    }

    [Fact]
    public async Task EnsureRequest_RepeatedCall_DedupesByCallerAndPolicy()
    {
        var store = new InMemoryApprovalStore();
        var first  = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var second = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Pending>(second);
        Assert.Equal(first.RequestId, ((ApprovalState.Pending)second).RequestId);
    }

    [Fact]
    public async Task ApproveAsync_TransitionsToActive()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        await store.ApproveAsync(pending.RequestId, "approver", note: null, default);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Active>(state);
    }

    [Fact]
    public async Task DenyAsync_TransitionsToDenied()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        await store.DenyAsync(pending.RequestId, "approver", "no", default);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Denied>(state);
    }

    [Fact]
    public async Task ActiveGrant_AfterExpiry_ReturnsDeniedExpired()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(),
            MakeSpec(grant: TimeSpan.FromMilliseconds(50)), MakeCtx(), default);
        await store.ApproveAsync(pending.RequestId, "a", null, default);
        await Task.Delay(150);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Denied>(state);
    }

    [Fact]
    public async Task WaitForDecision_TriggersOnApprove()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var waitTask = store.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(2), default).AsTask();
        await Task.Delay(50);
        await store.ApproveAsync(pending.RequestId, "a", null, default);
        var result = await waitTask;
        Assert.IsType<ApprovalState.Active>(result);
    }

    [Fact]
    public async Task ListPending_ReturnsOnlyPendingRequests()
    {
        var store = new InMemoryApprovalStore();
        var p1 = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller("a"), MakeSpec("p1"), MakeCtx(), default);
        await store.EnsureRequestAsync(MakeCaller("b"), MakeSpec("p2"), MakeCtx(), default);
        await store.ApproveAsync(p1.RequestId, "a", null, default);

        var pending = new List<PendingRequest>();
        await foreach (var r in store.ListPendingAsync(default)) pending.Add(r);
        Assert.Single(pending);
        Assert.Equal("p2", pending[0].PolicyName);
    }
}
```

**Step 2: Run — expect FAIL.**

```
dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~InMemoryApprovalStoreTests"
```

**Step 3: Implement** at `src/AI.Sentinel/Approvals/InMemoryApprovalStore.cs`:

```csharp
using System.Collections.Concurrent;
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>In-process approval store. Single-process only; state is lost on restart.</summary>
public sealed class InMemoryApprovalStore : IApprovalStore, IApprovalAdmin
{
    private readonly ConcurrentDictionary<string, Entry> _byRequestId = new();
    private readonly ConcurrentDictionary<(string callerId, string policyName), string> _dedupe = new();
    private readonly TimeProvider _time;

    public InMemoryApprovalStore() : this(TimeProvider.System) { }
    public InMemoryApprovalStore(TimeProvider time) { _time = time; }

    public ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
    {
        var key = (caller.Id, spec.PolicyName);
        if (_dedupe.TryGetValue(key, out var existingId) &&
            _byRequestId.TryGetValue(existingId, out var existing))
        {
            return ValueTask.FromResult(StateOf(existing));
        }

        var requestId = $"req-{Guid.NewGuid():N}";
        var now = _time.GetUtcNow();
        var entry = new Entry
        {
            RequestId = requestId,
            CallerId = caller.Id,
            PolicyName = spec.PolicyName,
            ToolName = context.ToolName,
            Args = context.Args,
            Justification = context.Justification,
            RequestedAt = now,
            GrantDuration = spec.GrantDuration,
            Status = EntryStatus.Pending,
            Decision = new TaskCompletionSource<ApprovalState>(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        _byRequestId[requestId] = entry;
        _dedupe[key] = requestId;
        return ValueTask.FromResult(StateOf(entry));
    }

    public async ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId, TimeSpan timeout, CancellationToken ct)
    {
        if (!_byRequestId.TryGetValue(requestId, out var entry))
            return new ApprovalState.Denied("unknown request", _time.GetUtcNow());
        if (entry.Status != EntryStatus.Pending) return StateOf(entry);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try { return await entry.Decision.Task.WaitAsync(cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return StateOf(entry); }
    }

    public ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct)
    {
        if (_byRequestId.TryGetValue(requestId, out var entry) && entry.Status == EntryStatus.Pending)
        {
            entry.Status = EntryStatus.Active;
            entry.ApprovedAt = _time.GetUtcNow();
            entry.Decision.TrySetResult(StateOf(entry));
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct)
    {
        if (_byRequestId.TryGetValue(requestId, out var entry) && entry.Status == EntryStatus.Pending)
        {
            entry.Status = EntryStatus.Denied;
            entry.DenyReason = reason;
            entry.DeniedAt = _time.GetUtcNow();
            entry.Decision.TrySetResult(StateOf(entry));
            _dedupe.TryRemove((entry.CallerId, entry.PolicyName), out _);
        }
        return ValueTask.CompletedTask;
    }

    public async IAsyncEnumerable<PendingRequest> ListPendingAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        foreach (var entry in _byRequestId.Values)
        {
            if (entry.Status == EntryStatus.Pending)
                yield return new PendingRequest(entry.RequestId, entry.CallerId, entry.PolicyName,
                    entry.ToolName, entry.Args, entry.RequestedAt, entry.Justification);
        }
        await ValueTask.CompletedTask;
    }

    private ApprovalState StateOf(Entry e)
    {
        var now = _time.GetUtcNow();
        return e.Status switch
        {
            EntryStatus.Active when e.ApprovedAt is { } a && a + e.GrantDuration > now
                => new ApprovalState.Active(a + e.GrantDuration),
            EntryStatus.Active
                => new ApprovalState.Denied("expired", now),
            EntryStatus.Denied
                => new ApprovalState.Denied(e.DenyReason ?? "denied", e.DeniedAt ?? now),
            _ => new ApprovalState.Pending(e.RequestId, $"sentinel://approve/{e.RequestId}", e.RequestedAt),
        };
    }

    private enum EntryStatus { Pending, Active, Denied }

    private sealed class Entry
    {
        public required string RequestId { get; init; }
        public required string CallerId { get; init; }
        public required string PolicyName { get; init; }
        public required string ToolName { get; init; }
        public System.Text.Json.JsonElement Args { get; init; }
        public string? Justification { get; init; }
        public DateTimeOffset RequestedAt { get; init; }
        public TimeSpan GrantDuration { get; init; }
        public EntryStatus Status { get; set; }
        public DateTimeOffset? ApprovedAt { get; set; }
        public DateTimeOffset? DeniedAt { get; set; }
        public string? DenyReason { get; set; }
        public required TaskCompletionSource<ApprovalState> Decision { get; init; }
    }
}
```

**Step 4: Run — expect PASS (all 7 tests).**

**Step 5: Commit.**

```bash
git add src/AI.Sentinel/Approvals/InMemoryApprovalStore.cs tests/AI.Sentinel.Tests/Approvals/
git commit -m "feat(approvals): InMemoryApprovalStore (IApprovalStore + IApprovalAdmin)"
```

---

### Task 1.6: `RequireApproval(...)` registration verb on `SentinelOptions`

**Files:**
- Modify: `src/AI.Sentinel/Authorization/SentinelOptionsAuthorizationExtensions.cs` (or create a new sibling extension file in `src/AI.Sentinel/Approvals/`)
- Modify: `src/AI.Sentinel/Authorization/ToolCallPolicyBinding.cs` (add `ApprovalSpec? ApprovalSpec` field)
- Test: `tests/AI.Sentinel.Tests/Approvals/SentinelOptionsApprovalExtensionsTests.cs` (new)

**Step 1: Read the existing binding shape.**

```
cat src/AI.Sentinel/Authorization/ToolCallPolicyBinding.cs
```

Then add a nullable `ApprovalSpec` field on it.

**Step 2: Write failing test.**

```csharp
using AI.Sentinel;
using AI.Sentinel.Approvals;
using Xunit;

namespace AI.Sentinel.Tests.Approvals;

public class SentinelOptionsApprovalExtensionsTests
{
    [Fact]
    public void RequireApproval_AddsBindingWithSpec()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("delete_database", spec =>
        {
            spec.PolicyName = "AdminApproval";
            spec.GrantDuration = TimeSpan.FromMinutes(30);
            spec.BackendBinding = "Database Administrator";
        });

        var binding = opts.GetAuthorizationBindings().Single(b => b.ToolNamePattern == "delete_database");
        Assert.NotNull(binding.ApprovalSpec);
        Assert.Equal("AdminApproval", binding.ApprovalSpec!.PolicyName);
        Assert.Equal("Database Administrator", binding.ApprovalSpec.BackendBinding);
    }
}
```

**Step 3: Run — expect FAIL** (no `RequireApproval` extension yet).

**Step 4: Implement** the extension method:

```csharp
// src/AI.Sentinel/Approvals/SentinelOptionsApprovalExtensions.cs
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals;

public static class SentinelOptionsApprovalExtensions
{
    /// <summary>Binds <paramref name="toolPattern"/> to an approval gate. The caller must be
    /// eligible (matching <see cref="IAuthorizationPolicy"/>) AND have an active approval.</summary>
    public static SentinelOptions RequireApproval(
        this SentinelOptions opts, string toolPattern, Action<ApprovalSpec> configure)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolPattern);
        ArgumentNullException.ThrowIfNull(configure);

        var spec = new ApprovalSpec { PolicyName = $"approval:{toolPattern}" };
        configure(spec);

        opts.AddAuthorizationBinding(new ToolCallPolicyBinding(
            toolNamePattern: toolPattern,
            policyName: spec.PolicyName,
            policy: AlwaysAllowPolicy.Instance,   // eligibility = trivial; approval gate is the real check
            approvalSpec: spec));
        return opts;
    }

    private sealed class AlwaysAllowPolicy : IAuthorizationPolicy
    {
        public static readonly AlwaysAllowPolicy Instance = new();
        public ValueTask<bool> IsAuthorizedAsync(ISecurityContext caller, CancellationToken ct = default)
            => ValueTask.FromResult(true);
    }
}
```

(Operators who want stricter eligibility can chain `.RequireToolPolicy(...)` before `.RequireApproval(...)`.)

**Step 5: Run — expect PASS.**

**Step 6: Commit.**

```bash
git add src/AI.Sentinel/Approvals/SentinelOptionsApprovalExtensions.cs src/AI.Sentinel/Authorization/ToolCallPolicyBinding.cs tests/AI.Sentinel.Tests/Approvals/SentinelOptionsApprovalExtensionsTests.cs
git commit -m "feat(approvals): opts.RequireApproval(toolPattern, spec) registration verb"
```

---

### Task 1.7: Wire `IApprovalStore` into `DefaultToolCallGuard`

**Files:**
- Modify: `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs` — register `InMemoryApprovalStore` if any binding has an `ApprovalSpec` and no `IApprovalStore` is registered yet; throw at startup if `RequireApproval` is configured but no store is wired in `Singleton` lifetime.
- Test: `tests/AI.Sentinel.Tests/Approvals/DefaultToolCallGuardApprovalTests.cs` (new)

**Step 1: Failing tests** that exercise the three branches (Active → Allow, Pending → RequireApproval, Denied → Deny) by injecting a fake `IApprovalStore`.

```csharp
// fake store returns whatever ApprovalState the test sets
internal sealed class FakeApprovalStore : IApprovalStore { ... }

[Fact] public async Task Authorize_ApprovalActive_ReturnsAllow() { ... }
[Fact] public async Task Authorize_ApprovalPending_ReturnsRequireApproval() { ... }
[Fact] public async Task Authorize_ApprovalDenied_ReturnsDeny() { ... }
[Fact] public async Task Authorize_NoApprovalSpec_BehavesLikeRequireToolPolicy() { ... }
```

**Step 2: Run — expect FAIL** (guard ignores `ApprovalSpec`).

**Step 3: Modify the guard's `AuthorizeAsync`** loop to consult `_approvalStore` when `binding.ApprovalSpec is not null`. See design doc §6.3 for the exact flow.

**Step 4: Modify `ServiceCollectionExtensions.AddAISentinel`** to:
- Auto-register `InMemoryApprovalStore` as singleton **only if** any binding has `ApprovalSpec` set and no `IApprovalStore` is registered.
- Throw `InvalidOperationException` if the developer explicitly removed the store but kept an `ApprovalSpec`.

**Step 5: Run — expect PASS.**

**Step 6: Commit.**

```bash
git commit -m "feat(approvals): DefaultToolCallGuard delegates to IApprovalStore for approval bindings"
```

---

### Task 1.8: `IChatClient` middleware (`AuthorizationChatClient`) blocks-and-waits on `RequireApproval`

**Files:**
- Modify: `src/AI.Sentinel/Authorization/AuthorizationChatClient.cs` — handle `RequireApprovalDecision`: call `_approvalStore.WaitForDecisionAsync` for up to `spec.WaitTimeout`, then re-evaluate. On timeout, throw `ToolCallAuthorizationException` with a clear "approval timed out" message.
- Test: extend `tests/AI.Sentinel.Tests/Authorization/AuthorizationChatClientTests.cs` with a "blocks until approval" scenario.

**Step 1-5 (TDD cycle):** failing test → minimal change → green → commit.

```bash
git commit -m "feat(approvals): chat-client middleware blocks-and-waits on RequireApproval"
```

---

## Stage 2 — `AI.Sentinel.Approvals.EntraPim` package

### Task 2.1: Scaffold the package

**Files:**
- Create: `src/AI.Sentinel.Approvals.EntraPim/AI.Sentinel.Approvals.EntraPim.csproj`
- Create: `src/AI.Sentinel.Approvals.EntraPim/EntraPimOptions.cs`
- Create: `tests/AI.Sentinel.Approvals.EntraPim.Tests/AI.Sentinel.Approvals.EntraPim.Tests.csproj`
- Modify: `AI.Sentinel.slnx`

**Step 1: Mirror the `AI.Sentinel.Sqlite` csproj.** Copy structure, change package id, references:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
    <PackageId>AI.Sentinel.Approvals.EntraPim</PackageId>
    <Description>Entra PIM-backed IApprovalStore — delegates AI.Sentinel approval requests
      to Microsoft Entra Privileged Identity Management via Microsoft Graph.</Description>
    <Version>0.1.0</Version>
    <Authors>Marcel Roozekrans</Authors>
    <PackageTags>ai;security;chatclient;approvals;entra;pim;graph</PackageTags>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
    <RepositoryUrl>https://github.com/MarcelRoozekrans/AI.Sentinel</RepositoryUrl>
    <RepositoryType>git</RepositoryType>
  </PropertyGroup>
  <ItemGroup>
    <None Include="..\..\README.md" Pack="true" PackagePath="\" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\AI.Sentinel\AI.Sentinel.csproj" />
    <PackageReference Include="Azure.Identity" Version="1.*" />
    <PackageReference Include="Microsoft.Graph" Version="5.*" />
    <PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="10.*" />
  </ItemGroup>
  <ItemGroup>
    <AssemblyAttribute Include="System.Runtime.CompilerServices.InternalsVisibleToAttribute">
      <_Parameter1>AI.Sentinel.Approvals.EntraPim.Tests</_Parameter1>
    </AssemblyAttribute>
  </ItemGroup>
</Project>
```

**Step 2: Add to `AI.Sentinel.slnx`** following the existing pattern.

**Step 3: Build empty package + tests project.**

```
dotnet build src/AI.Sentinel.Approvals.EntraPim
```

**Step 4: Commit.**

```bash
git commit -m "chore(entra-pim): scaffold AI.Sentinel.Approvals.EntraPim package"
```

---

### Task 2.2: `EntraPimOptions` + role resolution cache

`src/AI.Sentinel.Approvals.EntraPim/EntraPimOptions.cs`:

```csharp
namespace AI.Sentinel.Approvals.EntraPim;

public sealed class EntraPimOptions
{
    public required string TenantId { get; init; }
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan PollMaxBackoff { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Pre-resolved role display-name → roleDefinitionId map. Empty by default;
    /// the store resolves on first use and caches.</summary>
    public IDictionary<string, string> RoleNameToIdSeed { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
```

Cache implementation lives next to `EntraPimApprovalStore` in Task 2.3.

```bash
git commit -m "feat(entra-pim): EntraPimOptions"
```

---

### Task 2.3: `IGraphRoleClient` abstraction + fake-driven tests

**Files:**
- Create: `src/AI.Sentinel.Approvals.EntraPim/IGraphRoleClient.cs`
- Create: `tests/AI.Sentinel.Approvals.EntraPim.Tests/EntraPimApprovalStoreTests.cs`

**Step 1: Define the abstraction** so the store is unit-testable without hitting Graph.

```csharp
namespace AI.Sentinel.Approvals.EntraPim;

public interface IGraphRoleClient
{
    ValueTask<string?> ResolveRoleIdAsync(string displayName, CancellationToken ct);
    ValueTask<RoleScheduleSnapshot?> GetActiveAssignmentAsync(string principalId, string roleId, CancellationToken ct);
    ValueTask<bool> IsEligibleAsync(string principalId, string roleId, CancellationToken ct);
    ValueTask<string> CreateActivationRequestAsync(string principalId, string roleId, TimeSpan duration, string justification, CancellationToken ct);
    ValueTask<RoleRequestSnapshot> GetRequestStatusAsync(string requestId, CancellationToken ct);
}

public sealed record RoleScheduleSnapshot(string Status, DateTimeOffset? ExpiresAt);
public sealed record RoleRequestSnapshot(string Status, string? FailureReason);
```

**Step 2: Write failing tests** for `EntraPimApprovalStore` using a fake `IGraphRoleClient`:

```csharp
[Fact] public async Task EnsureRequest_ActiveSchedule_ReturnsActive() { ... }
[Fact] public async Task EnsureRequest_NoEligibility_ReturnsDenied() { ... }
[Fact] public async Task EnsureRequest_EligibleButNoActive_CreatesRequest_ReturnsPending() { ... }
[Fact] public async Task WaitForDecision_PollsUntilProvisioned() { ... }
[Fact] public async Task WaitForDecision_HonoursTimeoutOnPending() { ... }
[Fact] public async Task RoleResolution_FromDisplayName_CachedAfterFirstHit() { ... }
[Fact] public async Task PimStatus_PendingApproval_MapsToPending() { ... }
[Fact] public async Task PimStatus_Failed_MapsToDenied() { ... }
```

**Step 3: Run — expect FAIL.**

**Step 4: Implement `EntraPimApprovalStore`** (~150 lines). Follow design doc §7. Key behaviours:
- `EnsureRequestAsync`: resolve role → check active → check eligibility → POST request → return Pending. Cache role IDs.
- `WaitForDecisionAsync`: exponential backoff with jitter, capped at `PollMaxBackoff`.
- Status mapping per design doc §7.3.
- 401/403 surface as `ApprovalState.Denied("RoleManagement.ReadWrite.Directory consent required")`.
- 429 honours `Retry-After`.

**Step 5: Run — expect PASS.**

**Step 6: Commit.**

```bash
git commit -m "feat(entra-pim): EntraPimApprovalStore + IGraphRoleClient abstraction"
```

---

### Task 2.4: Real `MicrosoftGraphRoleClient` implementation

**Files:**
- Create: `src/AI.Sentinel.Approvals.EntraPim/MicrosoftGraphRoleClient.cs`

Implement against the official `Microsoft.Graph` SDK using `GraphServiceClient`. **No tests for this class** — it'd require real Graph or a heavyweight mock; cover via the abstract `IGraphRoleClient` tests in Task 2.3 plus a manual smoke test entry in the docs (Task 6.x).

```bash
git commit -m "feat(entra-pim): MicrosoftGraphRoleClient (live Graph SDK adapter)"
```

---

### Task 2.5: DI extension `AddSentinelEntraPimApprovalStore`

**Files:**
- Create: `src/AI.Sentinel.Approvals.EntraPim/EntraPimServiceCollectionExtensions.cs`

```csharp
public static IServiceCollection AddSentinelEntraPimApprovalStore(
    this IServiceCollection services, Action<EntraPimOptions> configure) { ... }
```

Wires:
- `EntraPimOptions` (singleton)
- `Azure.Identity.ChainedTokenCredential` (default chain)
- `MicrosoftGraphRoleClient` as `IGraphRoleClient`
- `EntraPimApprovalStore` as `IApprovalStore`

Test: smoke-build a `ServiceProvider` with the extension wired and assert `IApprovalStore` resolves to `EntraPimApprovalStore`.

```bash
git commit -m "feat(entra-pim): AddSentinelEntraPimApprovalStore DI extension"
```

---

## Stage 3 — `AI.Sentinel.Approvals.Sqlite` package

### Task 3.1: Scaffold

Mirror Task 2.1 with id `AI.Sentinel.Approvals.Sqlite`, dep `Microsoft.Data.Sqlite`, no Graph references.

```bash
git commit -m "chore(approvals-sqlite): scaffold package"
```

---

### Task 3.2: `SqliteApprovalStoreOptions` + schema

Mirror `SqliteAuditStoreOptions`. Schema needs a single table `approval_requests` with columns: `id`, `caller_id`, `policy_name`, `tool_name`, `args_json`, `justification`, `requested_at`, `grant_duration_ticks`, `status` (Pending/Active/Denied), `approved_at`, `denied_at`, `deny_reason`, `approver_id`. Plus indexes on `(caller_id, policy_name)` for dedupe and `status` for `ListPending`.

Use `journal_mode=WAL`, schema-init on first connection, `user_version` migration pattern.

```bash
git commit -m "feat(approvals-sqlite): SqliteApprovalStoreOptions + schema"
```

---

### Task 3.3: `SqliteApprovalStore` (TDD)

Mirror `SqliteAuditStore`'s structure:
- Single connection, `Pooling=false`
- `_writeLock` SemaphoreSlim for serialised writes
- DisposeAsync drains the lock with bounded wait
- `WaitForDecisionAsync` polls the DB on a 500 ms cadence
- `ApproveAsync` / `DenyAsync` `UPDATE` rows + remove dedupe entry on Deny
- All 7 InMemory tests + a "survives restart" test (close/reopen, state persists)

```bash
git commit -m "feat(approvals-sqlite): SqliteApprovalStore + IApprovalAdmin"
```

---

### Task 3.4: DI extension

Same shape as Task 2.5 — `AddSentinelSqliteApprovalStore(opts => ...)`.

```bash
git commit -m "feat(approvals-sqlite): AddSentinelSqliteApprovalStore DI extension"
```

---

## Stage 4 — Dashboard pending-approvals page + Approve/Deny endpoints

### Task 4.1: New dashboard handlers `ListApprovalsAsync` + `ApproveAsync` + `DenyAsync`

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs`
- Modify: `src/AI.Sentinel.AspNetCore/ApplicationBuilderExtensions.cs` (add the new routes to `MapAISentinel`)
- Test: extend `tests/AI.Sentinel.Tests/AspNetCore/`

**Step 1: Failing test** — POST `/sentinel/api/approvals/{requestId}/approve` with an `IApprovalAdmin`-implementing store transitions the request to active and a follow-up `EnsureRequestAsync` returns `Active`.

**Step 2: Implement.** Routes:
- `GET /api/approvals` — HTML fragment listing pending requests (table rows). Returns empty-state if no `IApprovalStore` is registered or `store is not IApprovalAdmin` (PIM case → render "Approve at PIM portal" message instead).
- `POST /api/approvals/{id}/approve` — calls `ApproveAsync`. Returns 200 + updated row.
- `POST /api/approvals/{id}/deny` — calls `DenyAsync`. Body: `{ "reason": "..." }`.

Approver identity comes from `HttpContext.User.Identity.Name ?? "anonymous"` for now — the dashboard auth wrap is the operator's responsibility (existing pattern, documented).

**Step 3: Run + commit.**

```bash
git commit -m "feat(aspnetcore): pending-approvals dashboard endpoints"
```

---

### Task 4.2: Dashboard UI — pending-approvals panel

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/wwwroot/index.html` — add a third panel after the live-event feed: "Pending Approvals" with HTMX poll on `/api/approvals` every 3 s, with Approve/Deny buttons triggering POSTs.
- Modify: `src/AI.Sentinel.AspNetCore/wwwroot/sentinel.css` — pending-approvals panel styling, optimistic-update animation on row click.
- For `EntraPimApprovalStore` (no `IApprovalAdmin`), render a single-row "Manage approvals in the PIM portal: <link>" instead of the table.

**Step 1-5:** TDD with browser-snapshot regression check (extend the regression-test harness from `scripts/capture-screenshots.mjs` to seed a pending approval and snapshot the rendered panel).

```bash
git commit -m "feat(aspnetcore): dashboard pending-approvals panel + Approve/Deny UI"
```

---

## Stage 5 — CLI integration

### Task 5.1: Single-file config loader

**Files:**
- Create: `src/AI.Sentinel/Approvals/Configuration/ApprovalConfig.cs` (record types + JSON deserialisation)
- Create: `src/AI.Sentinel/Approvals/Configuration/ApprovalConfigLoader.cs`

Records mirror the JSON shape from design doc §9.1:

```csharp
public sealed record ApprovalConfig(
    string Backend,
    string? TenantId,
    int DefaultGrantMinutes,
    string DefaultJustificationTemplate,
    bool IncludeConversationContext,
    Dictionary<string, ApprovalToolConfig> Tools);

public sealed record ApprovalToolConfig(string Role, int? GrantMinutes, bool? RequireJustification);
```

Loader reads `SENTINEL_APPROVAL_CONFIG`, expands `${ENV_VAR}` placeholders, validates required fields.

Tests: 5-7 cases (valid file, missing file, invalid JSON, missing required field, env-var expansion, glob tool patterns).

```bash
git commit -m "feat(approvals): ApprovalConfig JSON file loader"
```

---

### Task 5.2: Backend selector — translates config to DI registrations

**Files:**
- Create: `src/AI.Sentinel/Approvals/Configuration/ApprovalBackendSelector.cs`

Maps `config.Backend` ∈ `{"in-memory", "sqlite", "entra-pim", "none"}` to the right `AddSentinel*ApprovalStore` extension on `IServiceCollection`. Also iterates `config.Tools` and emits `opts.RequireApproval(toolPattern, spec => ...)` calls for each entry.

Used by all three CLI binaries.

```bash
git commit -m "feat(approvals): ApprovalBackendSelector — config → DI wiring"
```

---

### Task 5.3-5.5: Wire the selector into each CLI

For each of `sentinel-hook`, `sentinel-copilot-hook`, `sentinel-mcp`:
- Modify the `Program.cs` to call the selector at startup if `SENTINEL_APPROVAL_CONFIG` is set.
- Modify the decision-handler switch to add a `RequireApprovalDecision` arm.
- For hook CLIs: format stderr message "Approval required. Request ID: xxx. Approve at: <url>. Once approved, retry the tool call." Exit 2.
- For `sentinel-mcp`: read `SENTINEL_MCP_APPROVAL_WAIT_SEC` env (default 0). If > 0, call `WaitForDecisionAsync(spec.WaitTimeout)` and return on decision; else fail-fast with the same "approval required" message in the JSON-RPC error response.

Tests per CLI: a "RequireApproval result formats correctly" integration test using the existing CLI test pattern (`HookCliTests.cs`).

```bash
git commit -m "feat(claudecode-cli): handle RequireApproval — deny-with-receipt"
git commit -m "feat(copilot-cli):    handle RequireApproval — deny-with-receipt"
git commit -m "feat(mcp-cli):        handle RequireApproval — wait-and-block or fail-fast"
```

---

### Task 5.6: Bundle the EntraPim + Sqlite backends in each CLI

**Files:**
- Modify: `src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj`
- Modify: `src/AI.Sentinel.Copilot.Cli/AI.Sentinel.Copilot.Cli.csproj`
- Modify: `src/AI.Sentinel.Mcp.Cli/AI.Sentinel.Mcp.Cli.csproj`

Add `<ProjectReference>` to both `AI.Sentinel.Approvals.Sqlite` and `AI.Sentinel.Approvals.EntraPim`. Verify AOT publish still passes (the EntraPim package will introduce `IL2026/IL3050` warnings from Graph SDK reflection-based JSON; suppress per design doc §9.3 with `[UnconditionalSuppressMessage]`).

Run: `.github/workflows/aot-publish.yml` matrix locally (or just the CLI builds):

```
dotnet publish src/AI.Sentinel.ClaudeCode.Cli -c Release -r win-x64 -p:PublishAot=true
```

Expected: 0 IL warnings (after suppressions).

```bash
git commit -m "build(cli): bundle EntraPim + Sqlite approval backends in all three CLIs"
```

**Outcome (post-implementation note):** the actual IL diagnostics that surfaced were **IL2075** (reflective `Type.GetProperty` on `ODataError` inside EntraPim) and **IL2104** (assembly-level rollup from the transitive `Microsoft.Kiota.Serialization.Json` package). The plan predicted `IL2026/IL3050` based on Graph SDK reflection-based JSON; those didn't fire because EntraPim's reflective hot path is `GetProperty`, not the Kiota serializer (Kiota's own warnings roll up to IL2104 at the assembly boundary). The treatment chosen — per-call-site `[UnconditionalSuppressMessage("Trimming", "IL2075", ...)]` on the three EntraPim accessors plus `<NoWarn>IL2104</NoWarn>` scoped to the three CLI csprojs — is **tighter** than the plan envisioned: precisely justified per-call-site rather than a blanket suppression at the entrypoint, and IL2104 limited to the AOT-publish boundary so library trim diagnostics stay clean for non-AOT consumers.

---

## Stage 6 — Documentation

### Task 6.1: Website docs section

**Files:**
- Create: `website/docs/approvals/overview.md`
- Create: `website/docs/approvals/in-memory.md`
- Create: `website/docs/approvals/sqlite.md`
- Create: `website/docs/approvals/entra-pim.md`
- Create: `website/docs/approvals/dashboard.md`
- Create: `website/docs/approvals/cli-config.md`
- Modify: `website/sidebars.js` (add the new section)

Each page is operator-facing, ~200-400 words, with copy-pasteable code snippets. The Entra PIM page includes the `az` command for admin-consenting `RoleManagement.ReadWrite.Directory`.

```bash
git commit -m "docs(website): approvals section — overview + 5 backends/integrations"
```

---

### Task 6.2: Sample app — extend `samples/ConsoleDemo` with approval gate

Add a `delete_database` AIFunction registration + `opts.RequireApproval(...)` call + `AddSentinelInMemoryApprovalStore()`. Demonstrates the in-process middleware flow with `WaitForDecisionAsync`.

```bash
git commit -m "docs(samples): ConsoleDemo shows in-memory approval flow"
```

---

### Task 6.3: README — top-level mention + cross-link

Add a one-paragraph callout in `README.md` under the existing hook-positioning blockquote, linking into `website/docs/approvals/overview.md`. Include the headline value: "approval workflows for high-stakes tool calls (`delete_database`, `send_payment`) — in-memory, SQLite, or **native Entra PIM**".

```bash
git commit -m "docs(readme): approval-workflow callout + Entra PIM mention"
```

---

### Task 6.4: BACKLOG entry removal

Remove the line referencing PIM-style approval workflow from `docs/BACKLOG.md`:

```bash
sed -i '/PIM-style approval workflow/d' docs/BACKLOG.md
git add docs/BACKLOG.md
git commit -m "docs(backlog): remove PIM-style approval workflow — shipped"
```

---

## Final review checklist

- [ ] `dotnet test` is green on `net8.0`, `net9.0`, `net10.0` for every test project.
- [ ] AOT publish (`.github/workflows/aot-publish.yml`) is green for all three CLIs with 0 IL warnings.
- [ ] All three approval backends (`InMemory`, `Sqlite`, `EntraPim`) are exercised by their own test project.
- [ ] Dashboard regression-test screenshots include the new pending-approvals panel.
- [ ] README and website docs both reference the new feature with working anchors.
- [ ] `docs/BACKLOG.md` no longer lists "PIM-style approval workflow".
- [ ] Existing `RequireToolPolicy(...)` callers see zero behavioural change (verify via existing test suite).
- [ ] CS8509 — every `switch` over `AuthorizationDecision` either covers `RequireApprovalDecision` or uses `.AsBinary()` / `.IsAllowed()`.

---

## Stage estimates (from design doc §11)

| Stage | Tasks | Est. wall-clock |
|---|---|---|
| 1. Core | 1.1 – 1.8 | ~1 wk |
| 2. EntraPim | 2.1 – 2.5 | ~1-2 wk |
| 3. Sqlite | 3.1 – 3.4 | ~3 days |
| 4. Dashboard | 4.1 – 4.2 | ~1 wk |
| 5. CLI | 5.1 – 5.6 | ~1 wk |
| 6. Docs | 6.1 – 6.4 | ~3 days |

**Total:** ~6-7 weeks at 1 dev. Stages can be partially parallelised (3 starts after 1 ships; 2, 3, 4 can run concurrently).
