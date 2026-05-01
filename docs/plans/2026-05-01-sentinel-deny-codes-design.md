# `SentinelDenyCodes` constants + dashboard AUTHZ gate tightening — Design

**Status:** approved 2026-05-01
**Target version:** AI.Sentinel 1.6.1 (patch — pure refactor, zero behavioral change today)
**Source repo:** `C:\Projects\Prive\AI.Sentinel\` (currently 1.6.0)
**Backlog items addressed:** Two of the three 1.7.0 follow-ups filed in [`docs/plans/2026-05-01-async-structured-authorization.md`](2026-05-01-async-structured-authorization.md) plan retro:
- "Centralize the deny-code vocabulary as `SentinelDenyCodes` constants"
- "Tighten dashboard `StartsWith('AUTHZ-')` gate so future `AUTHZ-AUDIT`/`AUTHZ-WARN` detectors don't get a wrong-semantic `policy_denied` fallback"

The third 1.7.0 follow-up (MCP `error.data.policyCode` once SDK supports it) is gated on upstream `ModelContextProtocol` and stays deferred.

---

## Problem

PR #37 (1.6.0) introduced six well-known deny codes — `policy_denied`, `policy_not_registered`, `policy_exception`, `approval_required`, `approval_store_exception`, `approval_state_unknown` — emitted from `DefaultToolCallGuard` and propagated through audit, hook receipts, MCP error message, and dashboard. They appear as raw string literals in 7 production files. Two consequences:

1. **No single source of truth.** A maintainer adding a code (or renaming one) has to find every emit site by grep. Easy to miss one. Easy to typo.
2. **No discoverability.** Consumers reading the code or writing custom audit queries have to grep their way through the codebase to learn the canonical set.

PR #37 also introduced two visual signals on AUTHZ-DENY rows in the dashboard live feed: an orange-tinted row class (`audit-row-authz`) and a `<span class="badge code">` policy-code prefix. Both gates currently use `e.DetectorId.StartsWith("AUTHZ-", StringComparison.Ordinal)`. Today the only AUTHZ-* detector is `AUTHZ-DENY` so the gate is exact in practice. When future detectors land (`AUTHZ-AUDIT` for non-denying audit traces, `AUTHZ-WARN` for soft-flags), those rows would inherit the orange "denial" styling AND a misleading `policy_denied` badge fallback — a forward-compat bug.

## Goals

1. Centralize the six well-known deny codes as `public const string` fields on a new `SentinelDenyCodes` static class so consumers reference `SentinelDenyCodes.PolicyDenied` instead of scattered literals.
2. Tighten the dashboard's badge + row-class gates from `StartsWith("AUTHZ-")` to exact-match on `"AUTHZ-DENY"` (using the existing `AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId` constant). Filter chip stays loose.
3. Strict additivity: zero public-API change. `DenyDecision.Code` stays `string`. `Deny(name, reason, code)` still accepts arbitrary strings (third-party policies emit their own codes — `tenant_inactive`, `payment_threshold_exceeded`, etc.).

## Non-goals

- MCP `error.data.policyCode` — gated on upstream SDK; deferred.
- Code-fix analyzer that nudges authors toward `SentinelDenyCodes.X` instead of literals — defer until the canonical set proves stable.
- Migrating third-party policy authors to use the constants — they don't need to (the constants exist for clarity, not enforcement).
- Designing UI treatment for future `AUTHZ-AUDIT`/`AUTHZ-WARN` rows — that's their own work.

---

## Design decisions

### D1. Static class with `public const string` fields

```csharp
namespace AI.Sentinel.Authorization;

public static class SentinelDenyCodes
{
    public const string PolicyDenied            = "policy_denied";
    public const string PolicyNotRegistered     = "policy_not_registered";
    public const string PolicyException         = "policy_exception";
    public const string ApprovalRequired        = "approval_required";
    public const string ApprovalStoreException  = "approval_store_exception";
    public const string ApprovalStateUnknown    = "approval_state_unknown";
}
```

**Rejected alternatives:**
- **Strongly-typed `record struct DenyCode(string Value)`** — breaks the additive design. `AuthorizationFailure.Code` (the package contract) is `string`; converting at every boundary requires plumbing. Existing call sites (`Deny(name, reason, code)`, `AuthorizationDeny(..., policyCode)`) would need to change. The compile-time safety isn't worth the disruption when the wire format is already `string` everywhere downstream (audit DB column, JSON forwarders, dashboard HTML, hook stderr).
- **Public `enum`** — string conversion at every boundary; adding a code requires an enum + mapping update; can't represent third-party codes without escape hatches.

### D2. Tighten badge + row-class gates only (not filter chip)

Three gate sites in `DashboardHandlers.cs`:
- **Badge prefix render**: tighten to `string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal)`.
- **Row CSS class** (`audit-row-authz`): tighten to the same.
- **Filter chip** (`Authorization`): stays `StartsWith("AUTHZ-")` — operators clicking the filter plausibly want all AUTHZ-* rows, not just denials.

The badge and the orange row styling are both *denial-specific* visual signals — keeping them coupled to `AUTHZ-DENY` exactly is consistent. The filter chip is a *user-facing classification* and can reasonably broaden over time.

**Rejected alternatives:**
- **Tighten only the badge** — would diverge from the row class, producing an inconsistent visual: orange row + no badge = looks like a render bug.
- **Tighten all three** — pre-emptively dedicates the entire `AUTHZ-` UX to denials, removing flexibility for future taxonomy work. Users clicking "Authorization" wouldn't see audit rows.

### D3. SQL DEFAULT clause keeps the literal `'policy_denied'`

`SqliteSchema.cs` v2 migration applies `policy_code TEXT NOT NULL DEFAULT 'policy_denied'`. SQL DEFAULT clauses can't reference C# constants; the literal stays. This is fine — the wire-format guarantee (`SentinelDenyCodes.PolicyDenied == "policy_denied"`) is captured by the optional sanity test in §Testing.

---

## Architecture

### New file

`src/AI.Sentinel/Authorization/SentinelDenyCodes.cs` — ~30 lines, six XML-doc'd `public const string` fields per D1.

### Modified files (replace string literals)

1. **`src/AI.Sentinel/Authorization/AuthorizationDecision.cs`**
   - `DenyDecision`'s `Code` parameter default → `SentinelDenyCodes.PolicyDenied`.
   - `Deny(...)` factory's `code` parameter default → `SentinelDenyCodes.PolicyDenied`.
   - `AsBinary()` fold → `SentinelDenyCodes.ApprovalRequired`.

2. **`src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`**
   - `policy_not_registered` literal at the unregistered-policy branch → `SentinelDenyCodes.PolicyNotRegistered`.
   - `policy_exception` literal at the exception catch → `SentinelDenyCodes.PolicyException`.
   - `policy_denied` literal in the `failure.Code == AuthorizationFailure.DefaultDenyCode` canonicalization → `SentinelDenyCodes.PolicyDenied`.
   - `approval_store_exception` literal at the `EvaluateApprovalAsync` catch → `SentinelDenyCodes.ApprovalStoreException`.
   - `approval_state_unknown` literal at the unknown-state default → `SentinelDenyCodes.ApprovalStateUnknown`.
   - `policy_denied` literal at the `ApprovalState.Denied` branch → keep as the deliberate intent (real denial = `PolicyDenied`); use the constant.

3. **`src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs`**
   - `policyCode` parameter default → `SentinelDenyCodes.PolicyDenied`.

4. **`src/AI.Sentinel.ClaudeCode/HookAdapter.cs`**
   - `?? "policy_denied"` defensive fallback at the deny-receipt site → `?? SentinelDenyCodes.PolicyDenied`.
   - `policyCode: "approval_required"` at the audit-write site → `policyCode: SentinelDenyCodes.ApprovalRequired`.

5. **`src/AI.Sentinel.Copilot/CopilotHookAdapter.cs`** — same pattern as ClaudeCode (two sites).

6. **`src/AI.Sentinel.Mcp/ToolCallInterceptor.cs`** — same pattern (two sites: deny path + RequireApproval audit-write).

7. **`src/AI.Sentinel/Authorization/AuthorizationChatClient.cs`**
   - `?? "policy_denied"` defensive fallback at the deny-audit site → `?? SentinelDenyCodes.PolicyDenied`.

8. **`src/AI.Sentinel.AspNetCore/DashboardHandlers.cs`** — three changes:
   - `?? "policy_denied"` fallback in the badge render → `?? SentinelDenyCodes.PolicyDenied`.
   - `e.DetectorId.StartsWith("AUTHZ-", StringComparison.Ordinal)` gate for `isAuthz` (badge) → `string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal)`.
   - Same change for the row-class gate.
   - **Filter chip stays loose** with `StartsWith("AUTHZ-")`.

### Files NOT modified

- `src/AI.Sentinel.Sqlite/SqliteSchema.cs` — SQL DEFAULT clause keeps the literal `'policy_denied'` per D3.
- Test files — existing assertions are against the wire-format strings (`"policy_denied"`, etc.) and continue to pass; the constants resolve to the same values. Optional sanity test added per §Testing.

---

## Testing

### Required

Existing tests cover the wire-format contract (every emit site is asserted at the literal string). They keep passing because `SentinelDenyCodes.X` resolves to the same string at compile time. No behavioral test changes needed.

### Optional (recommended)

One sanity test in a new `tests/AI.Sentinel.Tests/Authorization/SentinelDenyCodesTests.cs`:

```csharp
public class SentinelDenyCodesTests
{
    [Fact]
    public void Constants_MatchWireFormat()
    {
        Assert.Equal("policy_denied",            SentinelDenyCodes.PolicyDenied);
        Assert.Equal("policy_not_registered",    SentinelDenyCodes.PolicyNotRegistered);
        Assert.Equal("policy_exception",         SentinelDenyCodes.PolicyException);
        Assert.Equal("approval_required",        SentinelDenyCodes.ApprovalRequired);
        Assert.Equal("approval_store_exception", SentinelDenyCodes.ApprovalStoreException);
        Assert.Equal("approval_state_unknown",   SentinelDenyCodes.ApprovalStateUnknown);
    }
}
```

This locks the wire format so a future "let's just rename to make codes more uniform" refactor would fail loudly. The test also serves as living documentation of the canonical set.

### Dashboard gate change

The gate change is a forward-compat tighten with zero behavioral change today (only `AUTHZ-DENY` exists). No new test needed. Existing dashboard tests continue to pass because they seed entries with `DetectorId == "AUTHZ-DENY"` (or its constant equivalent).

---

## Migration / backward compat

- **`SentinelDenyCodes` is purely additive.** No public-API changes (`DenyDecision.Code` stays `string`, `Deny(name, reason, code)` still takes `string`). Third-party consumers can ignore the constants and keep passing their own strings.
- **Dashboard gate tightening has zero behavioral effect today.** Only `AUTHZ-DENY` exists; `StartsWith("AUTHZ-")` and `== "AUTHZ-DENY"` produce identical row sets. The change is purely forward-compat for future AUTHZ-* detectors.
- **No SQLite schema change.** Schema v2 still uses the SQL literal `'policy_denied'` per D3.
- **No release-notes entry needed for downstream consumers** — the work is internal cleanup. release-please's `refactor:` prefix produces a "Refactors" CHANGELOG section but not a feature entry.

---

## Versioning

**AI.Sentinel 1.6.1** (patch). Conventional-commits prefixes:
- `refactor(authz):` for the constants centralization (multiple commits, one per file the implementer touches).
- `refactor(dashboard):` for the gate tightening.

release-please's existing config has `changelog-types` including `refactor` → "Refactors" section, so the CHANGELOG entry will be informative. Bump from 1.6.0 → 1.6.1.

If 1.6.0 hasn't shipped yet (the release-please PR may still be open at the time this lands), this work could merge before the 1.6.0 release-please PR and effectively be part of 1.6.0 instead — same outcome either way.

---

## Out of scope (deferred follow-ups)

- MCP `error.data.policyCode` — gated on `ModelContextProtocol` SDK exposing a `data`-bearing constructor.
- Code-fix analyzer — defer until the constants set proves stable.
- UI treatment for future `AUTHZ-AUDIT`/`AUTHZ-WARN` rows — designed by the work that adds those detectors, not pre-emptively here.
