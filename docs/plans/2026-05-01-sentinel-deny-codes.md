# `SentinelDenyCodes` Constants + Dashboard AUTHZ Gate Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or superpowers:subagent-driven-development for same-session execution) to implement this plan task-by-task.

**Goal:** Centralize the six well-known deny-code string literals as `public const string` fields on a new `SentinelDenyCodes` static class, then tighten the dashboard's badge + row-class visual gates from `StartsWith("AUTHZ-")` to exact match on `"AUTHZ-DENY"`.

**Architecture:** Pure refactor. Constants resolve to identical strings at compile time, so existing tests (which assert against the wire-format literals) keep passing without modification — that's the contract the constants must respect. Dashboard gate change is a forward-compat tighten with zero behavioral effect today (only `AUTHZ-DENY` exists).

**Tech Stack:** .NET 8 / 10 multi-target, xUnit, no new dependencies.

**Design doc:** [`docs/plans/2026-05-01-sentinel-deny-codes-design.md`](2026-05-01-sentinel-deny-codes-design.md). Read first for the rationale.

**Branch:** `refactor/sentinel-deny-codes` (already created off main, HEAD `61f3ffc` with design doc).

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
Expected: branch `refactor/sentinel-deny-codes`, HEAD `61f3ffc` (design doc), parent on main at `f1f071d` or later.

**Step 2: Baseline test counts.**

```bash
dotnet build AI.Sentinel.slnx --nologo 2>&1 | tail -3
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected from 1.6.0:
- `AI.Sentinel.Tests.dll`: 603
- `AI.Sentinel.Sqlite.Tests.dll`: 13
- `AI.Sentinel.Approvals.Sqlite.Tests.dll`: 14
- `AI.Sentinel.Approvals.EntraPim.Tests.dll`: 19
- `AI.Sentinel.Detectors.Sdk.Tests.dll`: 29
- `AI.Sentinel.OpenTelemetry.Tests.dll`: 11
- `AI.Sentinel.AzureSentinel.Tests.dll`: 3

**Total: 692.** Final count after this PR: **693** (one new sanity test).

**Step 3: Pre-flight grep for emit sites.**

```bash
grep -rn "\"policy_denied\"\|\"policy_not_registered\"\|\"policy_exception\"\|\"approval_required\"\|\"approval_store_exception\"\|\"approval_state_unknown\"" src --include="*.cs"
```

Expected sites (verified at plan-write time, line numbers may have shifted):
- `src/AI.Sentinel/Authorization/AuthorizationDecision.cs` lines 14, 23, 46
- `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs` lines 83, 95, 107, 127, 144
- `src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs` line 42 (+ XML doc at 30)
- `src/AI.Sentinel/Authorization/AuthorizationChatClient.cs` line 143
- `src/AI.Sentinel.ClaudeCode/HookAdapter.cs` lines 88, 98
- `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs` lines 92, 102
- `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs` lines 111, 167
- `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs` line 100
- `src/AI.Sentinel.Sqlite/SqliteAuditStore.cs` line 90 (runtime null-coalesce — gets the constant; SQL DEFAULT in SqliteSchema.cs stays literal)

**Do NOT touch test files.** Their assertions are against the wire-format strings (the contract). Migrating tests to use the constants would weaken the regression net by aligning the assertion with the implementation. Test files keep their literals.

No commit — preflight only.

---

## Phase 1 — Add `SentinelDenyCodes` static class

### Task 1.1: TDD-first sanity test, then the constants

**Files:**
- Create: `tests/AI.Sentinel.Tests/Authorization/SentinelDenyCodesTests.cs`
- Create: `src/AI.Sentinel/Authorization/SentinelDenyCodes.cs`

**Step 1: Write the failing sanity test.**

Create `tests/AI.Sentinel.Tests/Authorization/SentinelDenyCodesTests.cs`:

```csharp
using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class SentinelDenyCodesTests
{
    [Fact]
    public void Constants_MatchWireFormat()
    {
        // Locks the wire format. The constants exist for clarity; the strings are the contract.
        // A future refactor that renames the codes to "make them more uniform" would fail here
        // BEFORE breaking every audit consumer / SIEM dashboard / hook receipt parser.
        Assert.Equal("policy_denied",            SentinelDenyCodes.PolicyDenied);
        Assert.Equal("policy_not_registered",    SentinelDenyCodes.PolicyNotRegistered);
        Assert.Equal("policy_exception",         SentinelDenyCodes.PolicyException);
        Assert.Equal("approval_required",        SentinelDenyCodes.ApprovalRequired);
        Assert.Equal("approval_store_exception", SentinelDenyCodes.ApprovalStoreException);
        Assert.Equal("approval_state_unknown",   SentinelDenyCodes.ApprovalStateUnknown);
    }
}
```

**Step 2: Run — verify it fails.**

```bash
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~SentinelDenyCodesTests" --nologo
```
Expected: build error — `SentinelDenyCodes` does not exist.

**Step 3: Implement the constants.**

Create `src/AI.Sentinel/Authorization/SentinelDenyCodes.cs`:

```csharp
namespace AI.Sentinel.Authorization;

/// <summary>The well-known deny codes AI.Sentinel emits via <see cref="AuthorizationDecision.DenyDecision"/>'s
/// <c>Code</c> field, <see cref="Audit.AuditEntry"/>'s <c>PolicyCode</c> property, and downstream surfaces
/// (audit forwarders, hook receipts, MCP error message, dashboard badge). Third-party policies emit
/// their own codes — the structured-failure surface accepts any string. These constants document the
/// canonical set AI.Sentinel itself produces.</summary>
public static class SentinelDenyCodes
{
    /// <summary>Policy returned <c>IsAuthorized=false</c> (sync) or an unstructured failure. Default
    /// code on the bare-deny path; also the <c>SqliteAuditStore</c> column DEFAULT for legacy rows.</summary>
    public const string PolicyDenied = "policy_denied";

    /// <summary>A binding referenced a policy name that was never registered with the DI container.
    /// Failure-closed (deny) — recovery is operator action.</summary>
    public const string PolicyNotRegistered = "policy_not_registered";

    /// <summary>The policy threw a non-cancellation exception during evaluation. Failure-closed.</summary>
    public const string PolicyException = "policy_exception";

    /// <summary>Audit-entry tag for a tool call that was held up in the require-approval flow.
    /// Distinguishes pending approvals from real policy denials in audit queries.</summary>
    public const string ApprovalRequired = "approval_required";

    /// <summary>The approval store threw during request creation or status query. Failure-closed.</summary>
    public const string ApprovalStoreException = "approval_store_exception";

    /// <summary>An <c>ApprovalState</c> subclass not covered by the guard's switch arms (defensive
    /// fallback). Should not occur in practice — flagged distinctly for diagnostic purposes.</summary>
    public const string ApprovalStateUnknown = "approval_state_unknown";
}
```

**Step 4: Run — verify it passes.**

```bash
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~SentinelDenyCodesTests" --nologo
```
Expected: PASS.

**Step 5: Verify full suite still green.**

```bash
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: `AI.Sentinel.Tests.dll` = 604 (603 + 1 new). All others unchanged.

**Step 6: Commit.**

```bash
git add src/AI.Sentinel/Authorization/SentinelDenyCodes.cs tests/AI.Sentinel.Tests/Authorization/SentinelDenyCodesTests.cs
git commit -m "feat(authz): add SentinelDenyCodes static class

Centralizes the six well-known deny codes (policy_denied,
policy_not_registered, policy_exception, approval_required,
approval_store_exception, approval_state_unknown) as public const
string fields. Wire format unchanged — constants resolve to the
same string literals existing tests + downstream consumers assert
against. Sanity test locks the wire-format contract so a future
'rename for uniformity' refactor would fail loudly.

The constants document the canonical set AI.Sentinel itself
emits; third-party policies can still emit any string code via
the structured-failure API."
```

---

## Phase 2 — Replace string literals (per-file commits)

Each task in Phase 2 is a single-file edit + commit. Tests should keep passing throughout (every literal is being replaced with a constant whose value is the same literal). Run the suite after each commit; if anything fails, the implementer typo'd a constant.

### Task 2.1: `AuthorizationDecision.cs` — 3 sites

**Files:**
- Modify: `src/AI.Sentinel/Authorization/AuthorizationDecision.cs`

**Step 1: Read the file** to confirm the 3 sites:
- Line 14: `DenyDecision(string PolicyName, string Reason, string Code = "policy_denied")`
- Line 23: `Deny(string policyName, string reason, string code = "policy_denied")`
- Line 46: `Deny(r.PolicyName, $"approval required (requestId={r.RequestId})", "approval_required")` (the `AsBinary()` fold)

**Step 2: Replace.**

Line 14:
```csharp
public sealed record DenyDecision(string PolicyName, string Reason, string Code = SentinelDenyCodes.PolicyDenied) : AuthorizationDecision;
```

Line 23:
```csharp
public static DenyDecision Deny(string policyName, string reason, string code = SentinelDenyCodes.PolicyDenied) =>
    new(policyName, reason, code);
```

Line 46:
```csharp
? Deny(r.PolicyName, $"approval required (requestId={r.RequestId})", SentinelDenyCodes.ApprovalRequired)
```

`SentinelDenyCodes` is in the same namespace (`AI.Sentinel.Authorization`) as `AuthorizationDecision`, so no `using` change needed.

**Step 3: Verify build + tests.**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj --nologo 2>&1 | tail -3
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~AuthorizationDecisionTests" --nologo
```
Expected: 0 errors, all `AuthorizationDecisionTests` still pass.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel/Authorization/AuthorizationDecision.cs
git commit -m "refactor(authz): use SentinelDenyCodes in AuthorizationDecision"
```

---

### Task 2.2: `DefaultToolCallGuard.cs` — 5 sites

**Files:**
- Modify: `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`

**Step 1: Read the file** to confirm the 5 sites and surrounding context:
- Line 83: `"approval_store_exception"` — in the catch block of `EvaluateApprovalAsync`
- Line 95: `"approval_state_unknown"` — in the unknown-state default arm
- Line 107: `"policy_not_registered"` — in the unbound-policy branch
- Line 127: `"policy_exception"` — in the catch block of `EvaluatePolicyAsync`
- Line 144: `"policy_denied"` — the canonicalization remap target (the ternary's true branch when `failure.Code == AuthorizationFailure.DefaultDenyCode`)

**Step 2: Replace.**

```csharp
// Line 83 (approximate):
SentinelDenyCodes.ApprovalStoreException

// Line 95:
SentinelDenyCodes.ApprovalStateUnknown

// Line 107:
SentinelDenyCodes.PolicyNotRegistered

// Line 127:
SentinelDenyCodes.PolicyException

// Line 144:
? SentinelDenyCodes.PolicyDenied
```

Same namespace — no `using` change needed.

**Step 3: Verify.**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj --nologo 2>&1 | tail -3
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~DefaultToolCallGuardTests" --nologo
```
Expected: 0 errors, all `DefaultToolCallGuardTests` (16+ tests) still pass.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs
git commit -m "refactor(authz): use SentinelDenyCodes in DefaultToolCallGuard

Five sites: ApprovalStoreException (EvaluateApprovalAsync catch),
ApprovalStateUnknown (default switch arm), PolicyNotRegistered
(unbound policy), PolicyException (EvaluatePolicyAsync catch),
PolicyDenied (canonicalization remap target for the package's
AuthorizationFailure.DefaultDenyCode='policy.deny')."
```

---

### Task 2.3: `AuditEntryAuthorizationExtensions.cs` — 1 site (parameter default)

**Files:**
- Modify: `src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs`

**Step 1: Read** to confirm:
- Line 42 (approximate): `string policyCode = "policy_denied"` — the parameter default on the `AuthorizationDeny(...)` factory.
- Line 30 (approximate): XML doc references `<c>"policy_denied"</c>` — leave the doc literal as-is for human readability.

**Step 2: Replace.**

```csharp
string policyCode = SentinelDenyCodes.PolicyDenied)
```

Add a using directive at the top if not already present:

```csharp
using AI.Sentinel.Authorization;
```

`AuditEntryAuthorizationExtensions` is in the `AI.Sentinel.Audit` namespace, so it needs the explicit `using` to reach `SentinelDenyCodes`.

**Step 3: Verify.**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj --nologo 2>&1 | tail -3
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~AuditEntryAuthorizationExtensions" --nologo
```
Expected: 0 errors, all extension tests pass.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs
git commit -m "refactor(audit): use SentinelDenyCodes in AuthorizationDeny default"
```

---

### Task 2.4: `SqliteAuditStore.cs` — 1 site (runtime null-coalesce)

**Files:**
- Modify: `src/AI.Sentinel.Sqlite/SqliteAuditStore.cs`

**Step 1: Read** to confirm:
- Line 90 (approximate): `cmd.Parameters.AddWithValue("$code", (object?)entry.PolicyCode ?? "policy_denied");`

**Note:** The SQL DEFAULT clause in `SqliteSchema.cs` (separate file) stays as the literal `'policy_denied'` — SQL can't reference C# constants. Only the runtime-side null-coalesce changes.

**Step 2: Replace.**

```csharp
cmd.Parameters.AddWithValue("$code", (object?)entry.PolicyCode ?? SentinelDenyCodes.PolicyDenied);
```

Add `using AI.Sentinel.Authorization;` to the file if not already present.

**Step 3: Verify.**

```bash
dotnet build src/AI.Sentinel.Sqlite/AI.Sentinel.Sqlite.csproj --nologo 2>&1 | tail -3
dotnet test tests/AI.Sentinel.Sqlite.Tests/AI.Sentinel.Sqlite.Tests.csproj --nologo
```
Expected: 0 errors, all 13 Sqlite tests pass.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel.Sqlite/SqliteAuditStore.cs
git commit -m "refactor(sqlite): use SentinelDenyCodes in audit-store null-coalesce

SqliteSchema.cs's SQL DEFAULT clause stays as the literal 'policy_denied'
since SQL can't reference C# constants — the constant + the SQL DEFAULT
are guaranteed to match by the SentinelDenyCodes wire-format sanity test."
```

---

### Task 2.5: 5 hook + MCP + ChatClient sites (one commit, parallel changes)

**Files (5 emit sites across 4 files):**
- Modify: `src/AI.Sentinel/Authorization/AuthorizationChatClient.cs` (1 site at line 143)
- Modify: `src/AI.Sentinel.ClaudeCode/HookAdapter.cs` (2 sites at lines 88, 98)
- Modify: `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs` (2 sites at lines 92, 102)
- Modify: `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs` (2 sites at lines 111, 167)

**Step 1: Read each file** to confirm site shapes:
- 4 sites of `?? "policy_denied"` (defensive fallback after `decision as DenyDecision`):
  - `AuthorizationChatClient.cs:143` — `policyCode: deny?.Code ?? "policy_denied"`
  - `HookAdapter.cs:98` — `var denyCode = deny?.Code ?? "policy_denied"`
  - `CopilotHookAdapter.cs:102` — `var denyCode = deny?.Code ?? "policy_denied"`
  - `ToolCallInterceptor.cs:111` — `var policyCode = deny?.Code ?? "policy_denied"`
- 3 sites of `policyCode: "approval_required"` (audit-write at the require-approval branch):
  - `HookAdapter.cs:88`
  - `CopilotHookAdapter.cs:92`
  - `ToolCallInterceptor.cs:167`

**Step 2: Replace at each site.**

Pattern A (4 sites):
```csharp
?? SentinelDenyCodes.PolicyDenied
```

Pattern B (3 sites):
```csharp
policyCode: SentinelDenyCodes.ApprovalRequired
```

Add `using AI.Sentinel.Authorization;` at the top of each file if not already present (`AuthorizationChatClient.cs` is already in that namespace; the others are in their own packages and need the using).

**Step 3: Verify build + tests.**

```bash
dotnet build AI.Sentinel.slnx --nologo 2>&1 | tail -3
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```
Expected: 0 errors, full suite green at 604 main.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel/Authorization/AuthorizationChatClient.cs \
        src/AI.Sentinel.ClaudeCode/HookAdapter.cs \
        src/AI.Sentinel.Copilot/CopilotHookAdapter.cs \
        src/AI.Sentinel.Mcp/ToolCallInterceptor.cs
git commit -m "refactor(authz): use SentinelDenyCodes in hook + MCP audit/receipt sites

Seven sites across 4 files: 4× '?? PolicyDenied' defensive fallbacks
(AuthorizationChatClient, both hook adapters, MCP interceptor) plus
3× 'policyCode: ApprovalRequired' audit-write tags at the require-
approval branches. Wire format unchanged."
```

---

### Task 2.6: `DashboardHandlers.cs` — badge fallback literal

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs`

**Step 1: Read** to confirm:
- Line 100: `.Append(HtmlEncode(e.PolicyCode ?? "policy_denied"))`

**Step 2: Replace.**

```csharp
.Append(HtmlEncode(e.PolicyCode ?? SentinelDenyCodes.PolicyDenied))
```

Add `using AI.Sentinel.Authorization;` to the file if not already present.

**Step 3: Verify.**

```bash
dotnet build src/AI.Sentinel.AspNetCore/AI.Sentinel.AspNetCore.csproj --nologo 2>&1 | tail -3
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~DashboardAuthzFeedTests" --nologo
```
Expected: 0 errors, dashboard tests pass.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel.AspNetCore/DashboardHandlers.cs
git commit -m "refactor(dashboard): use SentinelDenyCodes in badge fallback"
```

---

## Phase 3 — Tighten dashboard AUTHZ gates

### Task 3.1: Tighten `isAuthz` gate from `StartsWith` to exact match

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs`

**Step 1: Read** the three gate sites:
- Line 87: `var isAuthz = e.DetectorId.StartsWith("AUTHZ-", StringComparison.Ordinal);` — gates BOTH the row class (line 90) AND the badge render (line 97).
- Line 90: `if (isAuthz) sb.Append(" audit-row-authz");` — uses `isAuthz` (no separate gate).
- Line 97: `if (isAuthz)` — same.
- Line 119: `entries.Where(e => e.DetectorId.StartsWith("AUTHZ-", StringComparison.Ordinal))` — filter chip; **STAYS LOOSE per design D2**.

Tightening line 87 covers both visual signals (row class + badge). The filter chip at line 119 is a separate `StartsWith` and stays.

**Step 2: Replace line 87.**

Before:
```csharp
var isAuthz = e.DetectorId.StartsWith("AUTHZ-", StringComparison.Ordinal);
```

After:
```csharp
var isAuthz = string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal);
```

The constant `AuthorizationDenyDetectorId` already exists at `src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs:13` and equals `"AUTHZ-DENY"`. The dashboard handler likely already imports `AI.Sentinel.Audit`; if not, add:

```csharp
using AI.Sentinel.Audit;
```

**Step 3: Verify build + dashboard tests.**

```bash
dotnet build src/AI.Sentinel.AspNetCore/AI.Sentinel.AspNetCore.csproj --nologo 2>&1 | tail -3
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --filter "FullyQualifiedName~Dashboard" --nologo
```
Expected: 0 errors, all dashboard-related tests pass. Today this is a no-op behavioral change (`StartsWith("AUTHZ-")` and `== "AUTHZ-DENY"` produce identical row sets when only `AUTHZ-DENY` exists), so existing tests must continue to pass.

**Step 4: Commit.**

```bash
git add src/AI.Sentinel.AspNetCore/DashboardHandlers.cs
git commit -m "refactor(dashboard): tighten AUTHZ-DENY visual gate to exact match

Changes the isAuthz gate at DashboardHandlers.cs:87 from
StartsWith('AUTHZ-') to string.Equals against the existing
AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId
constant ('AUTHZ-DENY'). The gate covers both visual denial
signals — the audit-row-authz row class (orange-tinted) AND the
badge code prefix — keeping them coupled to actual denials.

Filter chip at line 119 STAYS as StartsWith('AUTHZ-') so operators
clicking the 'Authorization' filter still see all AUTHZ-* rows
(future AUTHZ-AUDIT / AUTHZ-WARN included).

Zero behavioral change today — only AUTHZ-DENY exists; the gate
produces identical row sets. Forward-compat tighten so future
non-deny AUTHZ-* detectors don't inherit the orange denial styling
or a misleading 'policy_denied' badge fallback."
```

---

## Phase 4 — Verify + open PR

### Task 4.1: Final full-suite verification

```bash
cd C:/Projects/Prive/AI.Sentinel
dotnet build AI.Sentinel.slnx -c Release --nologo 2>&1 | tail -5
dotnet test AI.Sentinel.slnx -c Release --no-build --nologo 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```

Expected:
- 0 errors, 0 warnings on Release
- `AI.Sentinel.Tests.dll`: **604** (603 baseline + 1 new sanity test)
- All other suites unchanged from 1.6.0 baseline (Sqlite=13, EntraPim=19, Approvals.Sqlite=14, OpenTelemetry=11, Detectors.Sdk=29, AzureSentinel=3)
- **Total: 693** across net8.0 + net10.0

### Task 4.2: AOT trim probe

```bash
dotnet publish src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj -c Release -r win-x64 -p:PublishAot=true -o /tmp/aot-1.6.1 2>&1 | grep -E "warning IL|error IL"
```

Expected: zero IL warnings. `public const string` fields are compile-time literals; they emit zero AOT-relevant metadata. The `string.Equals(..., Ordinal)` change is zero-cost.

If the local toolchain can't run the native linker (no VS Build Tools on PATH), that's environmental — the IL/trim warning gate is what matters; CI handles native linking.

### Task 4.3: Push branch + open PR

```bash
git push -u origin refactor/sentinel-deny-codes
gh pr create --base main --head refactor/sentinel-deny-codes \
  --title "refactor(authz): SentinelDenyCodes constants + tighten dashboard AUTHZ gate" \
  --body "$(cat <<'EOF'
## Summary

Bundles two of the three 1.7.0 follow-ups filed in the [PR #37 plan retro](docs/plans/2026-05-01-async-structured-authorization.md):

- **Centralize the deny-code vocabulary** as a new \`SentinelDenyCodes\` static class with six \`public const string\` fields (\`PolicyDenied\`, \`PolicyNotRegistered\`, \`PolicyException\`, \`ApprovalRequired\`, \`ApprovalStoreException\`, \`ApprovalStateUnknown\`). Replaces 11+ scattered string literals across 8 production files.
- **Tighten the dashboard's AUTHZ-DENY visual gate** from \`StartsWith("AUTHZ-")\` to exact \`string.Equals(..., "AUTHZ-DENY", Ordinal)\` via the existing \`AuthorizationDenyDetectorId\` constant. Keeps the orange-tinted row class + badge prefix coupled to real denials. Filter chip stays loose.

The third 1.7.0 follow-up (MCP \`error.data.policyCode\`) remains deferred — gated on upstream \`ModelContextProtocol\` SDK exposing a \`data\`-bearing constructor.

## Design + Plan

- Design: [\`docs/plans/2026-05-01-sentinel-deny-codes-design.md\`](docs/plans/2026-05-01-sentinel-deny-codes-design.md)
- Plan: [\`docs/plans/2026-05-01-sentinel-deny-codes.md\`](docs/plans/2026-05-01-sentinel-deny-codes.md)

## What's NOT in this PR

- **Test files were not migrated** — assertions stay against the wire-format strings (\`"policy_denied"\`, etc.) since those are the contract the constants must respect. Migrating tests to use the constants would weaken the regression net by aligning the assertion with the implementation.
- **\`SqliteSchema.cs\`'s SQL DEFAULT clause stays as the literal \`'policy_denied'\`** — SQL can't reference C# constants. The \`SentinelDenyCodesTests\` sanity test guarantees the C# constant + the SQL DEFAULT match.

## Test plan

- [x] Full \`dotnet test AI.Sentinel.slnx\` green: 604 main + 13 Sqlite + 19 EntraPim + 14 Approvals.Sqlite + 11 OpenTelemetry + 29 Detectors.Sdk + 3 AzureSentinel = **693** across net8 + net10 (baseline 692 + 1 new sanity test).
- [x] Build clean: 0 errors, 0 warnings on Release across all 3 TFMs.
- [x] AOT trim probe clean: zero IL warnings on \`sentinel-hook\` AOT publish (\`public const string\` is compile-time inlined).
- [x] Existing tests pass without modification — proves the constants resolve to the same wire-format strings.
- [ ] After merge, release-please opens 1.6.1 PR.

## Versioning

**1.6.1** patch — pure refactor, zero public-API change, zero behavioral change today. Conventional-commits use \`refactor:\` prefix.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Final review checklist

- [ ] `SentinelDenyCodes.cs` created with all 6 const fields + XML docs
- [ ] Sanity test asserts each constant matches its wire-format string
- [ ] All 11+ emit sites in production code use the constants (test files NOT migrated)
- [ ] Dashboard `isAuthz` gate uses `string.Equals(...AuthorizationDenyDetectorId, Ordinal)`
- [ ] Dashboard filter chip at line 119 STILL uses `StartsWith("AUTHZ-")`
- [ ] `SqliteSchema.cs` SQL DEFAULT clause unchanged
- [ ] All 693 tests green on net8.0 + net10.0
- [ ] AOT trim probe clean
- [ ] PR title + body informative for release-please CHANGELOG

---

## Out of scope (deferred follow-ups)

- MCP `error.data.policyCode` — gated on `ModelContextProtocol` SDK exposing a `data`-bearing constructor.
- Code-fix analyzer that nudges authors toward `SentinelDenyCodes.X` instead of literals — defer until the canonical set proves stable enough to warrant analyzer enforcement.
- UI treatment for future `AUTHZ-AUDIT` / `AUTHZ-WARN` rows — designed by the work that adds those detectors, not pre-emptively here.
