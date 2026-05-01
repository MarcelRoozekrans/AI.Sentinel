# Async + Structured Authorization — Design

**Status:** approved 2026-05-01
**Target version:** AI.Sentinel 1.6.0 (minor bump, additive)
**Source repo:** `C:\Projects\Prive\AI.Sentinel\` (currently 1.5.0)
**Backlog items addressed:** "Async `IAuthorizationPolicy`" + the open follow-up filed in [`docs/plans/2026-04-30-zeroalloc-authorization-extraction.md`](2026-04-30-zeroalloc-authorization-extraction.md) ("uplift `DefaultToolCallGuard` to consume `EvaluateAsync` / `UnitResult<AuthorizationFailure>`").

---

## Problem

`DefaultToolCallGuard.AuthorizeAsync` is already an `async ValueTask<AuthorizationDecision>` method, but its policy invocation site at [`DefaultToolCallGuard.cs:106`](../../src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs#L106) calls the synchronous `policy.IsAuthorized(ctx)` and synthesises a hardcoded `"Policy denied"` string at line 117 when the policy returns `false`. Two consequences:

1. **I/O-bound policies block the dispatch thread.** A policy that needs to call out (tenant lookup, JWT validation against an external IdP, claims database) has no way to honor cancellation or surface its async behavior — it must either fake-sync via `.Result` (deadlock-prone, blocks threads) or throw `InvalidOperationException` (today's `TenantPolicy` README example).
2. **Policy-supplied failure detail is thrown away.** ZeroAlloc.Authorization 1.1.0 (the package AI.Sentinel 1.5.0 already depends on) ships `IAuthorizationPolicy.EvaluateAsync(ctx, ct)` returning `ValueTask<UnitResult<AuthorizationFailure>>` where `AuthorizationFailure` carries `string Code` + `string Reason`. A policy can raise `AuthorizationFailure { Code = "tenant_inactive", Reason = "Tenant 'acme' is in evicted state" }` — but the guard discards both and emits the literal `"Policy denied"`. Operators querying the audit log for `tenant_inactive` denials get nothing; everything looks identical.

## Goals

1. Switch `DefaultToolCallGuard` to call `policy.EvaluateAsync(ctx, ct)` — gets both async dispatch AND structured `Code` + `Reason` in a single call.
2. Surface the policy's `Code` end-to-end across every consumer-visible surface: decision model → audit log (durable) → hook receipts → MCP error body → dashboard live-feed UI.
3. Keep the change strictly additive. Existing 1.5.x consumers and existing sync-only `IAuthorizationPolicy` implementations (`AdminOnlyPolicy`, `NoSystemPathsPolicy`, user-defined policies) must keep working unchanged through ZeroAlloc.Authorization's default-interface-method bridges.

## Non-goals

- Designing the policy timeout (`opts.PolicyTimeout`) — separate backlog item.
- Source-gen-driven policy-name lookup — separate backlog item.
- Migrating sync-only policies to override `Evaluate` themselves — they keep working via DIM bridges; a future analyzer can nudge upgrades.
- Cross-process policy registry / dynamic policy reload — out of scope.
- Async on `IToolCallGuard.AuthorizeAsync` itself — already async; no signature change.

---

## Design decisions

### D1. Use `EvaluateAsync` (not `IsAuthorizedAsync`)

ZeroAlloc.Authorization 1.1.0 exposes a 2×2 matrix on `IAuthorizationPolicy`:

| | sync | async |
|---|---|---|
| **bool** | `IsAuthorized(ctx)` | `IsAuthorizedAsync(ctx, ct)` |
| **structured** | `Evaluate(ctx)` → `UnitResult<AuthorizationFailure>` | `EvaluateAsync(ctx, ct)` → `ValueTask<UnitResult<AuthorizationFailure>>` |

`EvaluateAsync` collects both upgrades the design needs — no reason to take only one. Default-interface-method bridges in the package make existing `IsAuthorized`-only policies seamlessly consumable: the DIM produces a default `AuthorizationFailure { Code = AuthorizationFailure.DefaultDenyCode, Reason = ... }` when the policy returns `false`.

**Rejected:** stopping at `IsAuthorizedAsync` (gets async but throws away the Code signal — defeats the structured-result design that ZeroAlloc.Authorization 1.1.0 explicitly added).

### D2. Add `Code` to `DenyDecision` (additive, with default)

```csharp
public sealed record DenyDecision(
    string PolicyName,
    string Reason,
    string Code = "policy_denied") : AuthorizationDecision;

public static DenyDecision Deny(string policyName, string reason, string code = "policy_denied")
    => new(policyName, reason, code);
```

The default value preserves all existing call sites that pass `(name, reason)` positionally and all named-deconstruction patterns. **Caveat:** *positional* deconstruction patterns (`case DenyDecision(var n, var r):`) become ambiguous because positional patterns require all parameters; pre-flight grep across the solution confirms no such patterns exist today.

**Rejected:**
- Squashing code into reason (`reason = $"[{code}] {reason}"`) — loses the machine-readable axis used for audit filtering and operator alerting.
- Leaving the code on the floor — defeats the whole point of switching to `EvaluateAsync`.

### D3. Audit schema migration: NOT NULL with default `'policy_denied'`

`SqliteAuditStore` schema gains:

```sql
ALTER TABLE audit_entries ADD COLUMN policy_code TEXT NOT NULL DEFAULT 'policy_denied';
```

The default value `'policy_denied'` is faithful to what every pre-1.6 denial actually was — the old hardcoded reason. Existing operators see no data loss; their pre-1.6 denials retroactively carry the literal `'policy_denied'` code, which lets them distinguish "no code recorded" (literal `'policy_denied'`) from policies that explicitly raised `'policy_denied'` only by inspection of the reason text. This is a tiny ambiguity worth accepting in exchange for a NOT NULL contract that downstream queries don't have to wrap in `COALESCE`.

**Rejected:**
- Nullable column — forces every consumer query to handle three-state logic.
- Backfill from `reason` — fragile data-rewrite parsing; ages badly.

### D4. Full propagation (Scope C from the brainstorm)

Every consumer-visible surface that today emits `Reason` will also emit `Code`. The five touch points are:

| Surface | What changes |
|---|---|
| `AuditEntry` data model | Optional `PolicyCode` property (record param with default `null`) |
| `AuditEntryAuthorizationExtensions.AuthorizationDeny` | Adds `policyCode` parameter; propagates into the entry |
| `SqliteAuditStore` schema + read/write | New column + populated reads |
| NDJSON / AzureSentinel / OpenTelemetry forwarders | One-line addition to each per-forwarder JSON DTO |
| `sentinel-hook` / `sentinel-copilot-hook` stderr receipt | Format becomes `Authorization denied [code]: reason` |
| `sentinel-mcp` JSON-RPC error body | `data.policyCode` field added (top-level `code` stays the JSON-RPC reserved `-32000`) |
| Dashboard live-event-feed | Inline `<span class="badge code">code</span>` prefix on the AUTHZ-DENY row's Reason cell |

**Rejected scopes:**
- Decision-only — burns the structured Code signal at consumption layer.
- Decision + audit — covers the durable signal but leaves operators flying blind in the dashboard / hook receipts during incident triage.

### D5. Dashboard: inline badge prefix (not new column, not tooltip)

Reason cell becomes:

```html
<span class="badge code">tenant_inactive</span> Tenant 'acme' is in evicted state
```

Existing `tr.audit-row-authz` orange-border + tinted-background styling untouched. New `.badge.code` CSS rule (mono font, muted background, smaller font-size). Mobile breakpoint at 480px keeps the same column-hide list — no real-estate cost.

**Rejected:**
- New `Code` column — burns mobile width and adds a sortable-column maintenance burden for ~6 distinct codes the system will ever produce.
- Hover-tooltip — hides the data behind a gesture nobody discovers.

---

## Architecture

### Type changes

**`AuthorizationDecision.DenyDecision`** ([`src/AI.Sentinel/Authorization/AuthorizationDecision.cs`](../../src/AI.Sentinel/Authorization/AuthorizationDecision.cs))

```csharp
public sealed record DenyDecision(string PolicyName, string Reason, string Code = "policy_denied")
    : AuthorizationDecision;

public static DenyDecision Deny(string policyName, string reason, string code = "policy_denied")
    => new(policyName, reason, code);
```

**`DefaultToolCallGuard.AuthorizeAsync` core loop** ([`src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs:106`](../../src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs#L106))

```csharp
var result = await policy.EvaluateAsync(ctx, ct).ConfigureAwait(false);
if (result.IsSuccess)
{
    matched = true;
    continue;
}
var failure = result.Error;
return AuthorizationDecision.Deny(name, failure.Reason, failure.Code);
```

`UnitResult<AuthorizationFailure>` exposes `IsSuccess` / `Error` (per ZeroAlloc.Results 0.1.4 conventions). Cancellation token (`ct`) is already in scope from the surrounding `AuthorizeAsync` parameter.

**`ToolCallAuthorizationPolicy`** abstract base — no change. Subclass authors who want a structured Code can override `Evaluate(ISecurityContext)` directly when they upgrade.

### Audit propagation

**`AuditEntry`** ([`src/AI.Sentinel/Audit/AuditEntry.cs`](../../src/AI.Sentinel/Audit/AuditEntry.cs)) — gain optional `PolicyCode` (record param with default `null`). Non-AUTHZ entries remain `null`; AUTHZ entries carry the policy-supplied code.

**`AuditEntryAuthorizationExtensions.AuthorizationDeny`** — adds `policyCode` parameter (default `"policy_denied"`).

**`SqliteAuditStore` schema migration** — bumps `PRAGMA user_version` from N to N+1. Migration step: `ALTER TABLE audit_entries ADD COLUMN policy_code TEXT NOT NULL DEFAULT 'policy_denied'`. Read path adds `policy_code` to the `SELECT` and populates `AuditEntry.PolicyCode`.

**NDJSON / AzureSentinel / OpenTelemetry forwarders** — `AuditEntry.PolicyCode` is part of the entry; per-forwarder JSON DTO adds the field. `JsonSerializerContext` source-gen tables regenerate from the updated DTOs.

### Hook receipts

`sentinel-hook` and `sentinel-copilot-hook` stderr emit one-line "deny with receipt" today. New format:

```
Authorization denied [tenant_inactive]: Tenant 'acme' is in evicted state (policy=TenantActive, requestId=req-123, approvalUrl=...)
```

Code in square brackets between the verb and reason. The existing space-separated `key=value` trailer is unchanged.

### MCP JSON-RPC error body

`sentinel-mcp` proxy fail-fast path emits a JSON-RPC error envelope. The top-level `error.code` stays `-32000` (JSON-RPC reserved range for application errors). New shape of `error.data`:

```json
{
  "policyName": "TenantActive",
  "policyCode": "tenant_inactive",
  "reason": "Tenant 'acme' is in evicted state",
  "approvalRequired": false
}
```

Existing fields (`policyName`, `reason`, `approvalRequired`, etc.) keep their semantics. `policyCode` is purely additive.

### Dashboard

Live event feed AUTHZ-DENY row template adds:

```html
<td><span class="badge code">{{ entry.PolicyCode }}</span> {{ entry.Reason }}</td>
```

CSS rule (added to `wwwroot/sentinel.css`):

```css
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

No new column. No tooltip. Mobile layout unchanged.

---

## Test plan

| Area | New / changed |
|---|---|
| `DefaultToolCallGuardTests` | +3: structured Code propagates from policy; default code applied when policy returns `IsAuthorized = false` (via DIM bridge); cancellation honored |
| `AuditEntryAuthorizationExtensionsTests` | +2: Code persisted; default applied when omitted |
| `SqliteAuditSchemaTests` | +1: migration from previous schema version backfills existing rows with `'policy_denied'` and `ALTER TABLE` succeeds without locking |
| `SqliteAuditStoreTests` | +1: AUTHZ entry round-trips with policy-supplied Code |
| `NdjsonFileAuditForwarderTests` / Azure Sentinel / OTel | Update existing JSON snapshot assertions to include `"policyCode"` field |
| `HookCliTests` (ClaudeCode + Copilot) | Update receipt-string expectations from `Denied:` to `Authorization denied [policy_denied]:`; +1 test verifying explicit policy code surfaces |
| `McpCliTests` (or AuthorizationTests) | +1: JSON-RPC error `data.policyCode` populated |
| `DashboardApprovalsTests` (or feed render tests) | +1 snapshot test for the badge HTML |
| Existing tests asserting against `"Policy denied"` literal | Update reason expectations in ~6 test files |

Estimated **~10 test files touched, ~12 new tests**. Full suite goes from 668 → ~680.

---

## Migration / backward compat

- **DenyDecision** — additive; default value preserves all named-deconstruction patterns. Pre-flight grep confirmed no positional deconstruction in the solution.
- **AuditEntry.PolicyCode** — additive optional record param; non-AUTHZ entries keep emitting `null`.
- **SqliteAuditStore schema** — `ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT ...` is a non-locking instant operation; existing audit DB files upgrade transparently on first read after 1.6.0 deploy.
- **Hook receipt format** — operator-facing stderr format is not a stable API; adding `[code]` prefix is a UX wobble, not a breaking change.
- **MCP JSON-RPC `data.policyCode`** — purely additive; existing consumers ignoring the field keep working.
- **Dashboard** — pure HTML/CSS addition.
- **Existing `IAuthorizationPolicy` implementations** — keep working unchanged via the package's DIM bridges. Authors who want explicit structured codes override `Evaluate` when they're ready.

---

## Out of scope (deferred follow-ups)

- `opts.PolicyTimeout` — separate backlog item ("Policy timeout" under Policy & Authorization).
- Source-gen-driven policy-name lookup — separate backlog item.
- `opts.AuditAllows` — different feature, separate slice.
- Code-fix analyzer that nudges sync-only policy authors toward `Evaluate` overrides — when a real customer has a structured-code use case.
- Async on `IToolCallGuard` itself — already async, no change needed.

---

## Versioning

**AI.Sentinel 1.6.0** — minor bump.

Justification: every change is additive at the public API level. Default values on `DenyDecision.Code` and `AuthorizationDeny.policyCode` preserve all 1.5.x call sites. Audit schema migration is forward-compatible. Hook receipt format and MCP error body are operator-facing wobbles, not API contracts.

When the merge lands on `main`, release-please sees the `feat:` commits and opens a 1.6.0 PR.
