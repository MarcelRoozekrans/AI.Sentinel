# PIM-Style Approval Workflow — Design

**Status:** Design approved · awaiting implementation plan
**Date:** 2026-04-29
**Author:** Marcel Roozekrans (with Claude)
**Brainstorming session:** [internal]

---

## 1. Problem statement

Agentic AI in production runs into a wall when its tool calls touch real
data, money, or infrastructure: `delete_database`, `send_payment`,
`deploy_to_prod`, `kubectl apply`. AI.Sentinel's current `IToolCallGuard`
is a binary Allow/Deny gate — there's no third option for "the caller is
eligible but a human needs to approve this specific invocation
out-of-band before it goes through."

Enterprise organisations already solve this for human-operated systems
via **privileged identity management (PIM)** — Microsoft Entra PIM,
ServiceNow access requests, Slack-based deploy gates, etc. AI.Sentinel
should integrate with these systems rather than ship a parallel approval
mechanism that operators have to learn.

## 2. Goals

- Add a `RequireApproval` decision tier to `IToolCallGuard` alongside
  Allow/Deny, with structured information (request ID, approval URL)
  so hosts can decide whether to wait, fail-fast, or hand off.
- Pluggable `IApprovalStore` abstraction with multiple backends:
  in-memory (dev), SQLite (CLI deployments), Microsoft Entra PIM
  (enterprise).
- Native CLI support — `sentinel-hook`, `sentinel-copilot-hook`,
  `sentinel-mcp` all participate in the approval flow.
- Strictly additive over the existing v1 contract. Existing users see
  zero behavioural change unless they opt into the new verb
  (`opts.RequireApproval(...)`).

## 3. Non-goals

- A custom approval UI that competes with PIM's portal. We render
  Approve/Deny buttons in our dashboard for stores that own approval
  state (InMemory, SQLite); for EntraPim we link to the PIM portal.
- A federation layer that unifies multiple approval backends into one
  feed. One backend per pipeline, picked at registration time.
- Approver MFA enforcement. PIM enforces this; our InMemory/SQLite
  stores don't and document that limitation.
- Breaking changes to `AuthorizationDecision` consumers — the new
  third sealed-record case is opt-in via a default-arm or helper
  extension method (see §10).

## 4. Architecture overview

```
┌────────────────────────────────────────────────────────────────────┐
│  Host: SentinelChatClient / sentinel-mcp / sentinel-hook / etc.    │
│                                                                    │
│   ┌─────────────────────┐         ┌─────────────────────────────┐  │
│   │ IToolCallGuard      │  ─────► │ IApprovalStore              │  │
│   │ (existing)          │         │ - EnsureRequestAsync        │  │
│   │                     │         │ - WaitForDecisionAsync      │  │
│   │ AuthorizeAsync      │         │                             │  │
│   │  ├─ Allow           │         │ Implementations:            │  │
│   │  ├─ Deny            │         │  - InMemoryApprovalStore    │  │
│   │  └─ RequireApproval │         │  - SqliteApprovalStore      │  │
│   └─────────────────────┘         │  - EntraPimApprovalStore    │  │
│                                   └─────────────────────────────┘  │
│                                              │                     │
│                                              ▼                     │
│                                    ┌─────────────────────┐         │
│                                    │ IApprovalAdmin      │         │
│                                    │ (optional surface)  │         │
│                                    │ - ApproveAsync      │         │
│                                    │ - DenyAsync         │         │
│                                    │ - ListPendingAsync  │         │
│                                    └─────────────────────┘         │
└────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
                       For EntraPim: Microsoft Graph API
                       For InMemory/Sqlite: dashboard Approve/Deny page
```

## 5. Package map

| Package | Status | Contents |
|---|---|---|
| `AI.Sentinel` (core) | extended | `IApprovalStore`, `IApprovalAdmin`, `ApprovalState`, `ApprovalSpec`, `ApprovalContext`, `PendingRequest`, `InMemoryApprovalStore`, `AddSentinelInMemoryApprovalStore()` extension, `RequireApproval` decision tier, `RequireApproval(...)` registration verb |
| `AI.Sentinel.Approvals.Sqlite` | new | `SqliteApprovalStore`, `AddSentinelSqliteApprovalStore(opts => ...)` |
| `AI.Sentinel.Approvals.EntraPim` | new | `EntraPimApprovalStore`, `AddSentinelEntraPimApprovalStore(opts => ...)`, Graph API client, role-name resolution cache |
| `AI.Sentinel.AspNetCore` | extended | Pending-approvals dashboard page + Approve/Deny endpoints (gated on `store is IApprovalAdmin`); falls back to "Approve at PIM portal" link when the store doesn't implement `IApprovalAdmin` |

InMemory ships in core because it's small (~100 LoC), self-contained
for tests, and is the natural fallback for in-process middleware
deployments.

## 6. API surface

### 6.1 Decision tier (sealed hierarchy)

```csharp
public abstract record AuthorizationDecision
{
    public sealed record Allow : AuthorizationDecision;

    public sealed record Deny(string PolicyName, string Reason)
        : AuthorizationDecision;

    /// <summary>
    /// The caller is eligible but must obtain out-of-band approval first.
    /// The host (middleware / MCP proxy / CLI hook) decides what to do:
    /// block-and-wait, fail-fast-with-receipt, or hand the request off
    /// to a UI.
    /// </summary>
    public sealed record RequireApproval(
        string PolicyName,
        string RequestId,
        string ApprovalUrl,
        DateTimeOffset RequestedAt)
        : AuthorizationDecision;
}
```

### 6.2 Registration verbs

```csharp
// Existing — binary gate, unchanged behaviour:
opts.RequireToolPolicy("delete_user", "AdminPolicy");

// New — eligibility gate + approval gate:
opts.RequireApproval("delete_database", spec =>
{
    spec.PolicyName       = "AdminApproval";
    spec.GrantDuration    = TimeSpan.FromMinutes(15);
    spec.RequireJustification = true;
    spec.WaitTimeout      = TimeSpan.FromMinutes(5);
    spec.BackendBinding   = "Database Administrator";  // PIM role name
});

// Stack: eligibility check first (rejects fast), then approval gate:
opts.RequireToolPolicy("admin/*", "InternalNetworkPolicy")
    .RequireApproval("admin/destroy_*", spec => { ... });
```

### 6.3 Decision flow inside `IToolCallGuard.AuthorizeAsync`

```csharp
public async ValueTask<AuthorizationDecision> AuthorizeAsync(
    ISecurityContext caller, string toolName, JsonElement args,
    CancellationToken ct)
{
    foreach (var binding in _bindings.Where(b => b.Matches(toolName)))
    {
        // 1. Eligibility check (existing)
        if (!await binding.Policy.IsAuthorizedAsync(caller))
            return new Deny(binding.PolicyName, binding.Reason);

        // 2. Approval gate (new)
        if (binding.ApprovalSpec is { } spec)
        {
            var state = await _approvalStore.EnsureRequestAsync(
                caller, spec, new ApprovalContext(toolName, args, justification),
                ct);

            return state switch
            {
                ApprovalState.Active            => new Allow(),
                ApprovalState.Pending p         => new RequireApproval(
                    spec.PolicyName, p.RequestId, p.ApprovalUrl, p.RequestedAt),
                ApprovalState.Denied d          => new Deny(spec.PolicyName, d.Reason),
            };
        }
    }
    return new Allow();
}
```

Properties:
- Eligibility before approval — unauthorised callers never spam Graph
  API with PIM activation requests.
- Store dedupes on `(caller.Id, spec.PolicyName)` — repeated tool
  calls during the active window go through with no extra round-trips.
- Mental model matches PIM: one active "Database Administrator" grant
  covers all admin tools, not per-(tool, args).

### 6.4 `IApprovalStore` contract

```csharp
public interface IApprovalStore
{
    /// <summary>
    /// Returns the current state for (caller, policyName). Idempotent: doesn't
    /// create duplicate pending requests when called repeatedly.
    /// </summary>
    ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller,
        ApprovalSpec spec,
        ApprovalContext context,
        CancellationToken ct);

    /// <summary>
    /// Blocks until the named request transitions to Active or Denied, or the
    /// timeout elapses. Cooperative.
    /// </summary>
    ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId,
        TimeSpan timeout,
        CancellationToken ct);
}

public interface IApprovalAdmin
{
    ValueTask ApproveAsync(string requestId, string approverId, string? note,
        CancellationToken ct);

    ValueTask DenyAsync(string requestId, string approverId, string reason,
        CancellationToken ct);

    IAsyncEnumerable<PendingRequest> ListPendingAsync(CancellationToken ct);
}

// Concrete bindings:
//   InMemoryApprovalStore : IApprovalStore, IApprovalAdmin
//   SqliteApprovalStore   : IApprovalStore, IApprovalAdmin
//   EntraPimApprovalStore : IApprovalStore                 (no admin — PIM owns)
```

### 6.5 State + supporting types

```csharp
public abstract record ApprovalState
{
    public sealed record Active(DateTimeOffset ExpiresAt) : ApprovalState;
    public sealed record Pending(string RequestId, string ApprovalUrl,
        DateTimeOffset RequestedAt) : ApprovalState;
    public sealed record Denied(string Reason, DateTimeOffset DeniedAt) : ApprovalState;
}

public sealed class ApprovalSpec
{
    public required string PolicyName { get; init; }
    public TimeSpan GrantDuration { get; init; } = TimeSpan.FromMinutes(15);
    public bool RequireJustification { get; init; } = true;
    public TimeSpan WaitTimeout { get; init; } = TimeSpan.FromMinutes(5);
    public string? BackendBinding { get; init; }
}

public sealed record ApprovalContext(
    string ToolName,
    JsonElement Args,
    string? Justification);

public sealed record PendingRequest(
    string RequestId,
    string CallerId,
    string PolicyName,
    string ToolName,
    JsonElement Args,
    DateTimeOffset RequestedAt,
    string? Justification);
```

## 7. EntraPim backend specifics

### 7.1 Graph endpoints

| Operation | Endpoint | Frequency |
|---|---|---|
| Check active grant | `GET /roleManagement/directory/roleAssignmentSchedules?$filter=principalId eq '{id}' and roleDefinitionId eq '{roleId}' and status eq 'Provisioned'` | Every `EnsureRequestAsync` |
| Verify eligibility | `GET /roleManagement/directory/roleEligibilitySchedules?$filter=principalId eq '{id}' and roleDefinitionId eq '{roleId}'` | Before creating a request |
| Create activation request | `POST /roleManagement/directory/roleAssignmentScheduleRequests` | When no active + no pending found |
| Poll request status | `GET /roleManagement/directory/roleAssignmentScheduleRequests/{id}` | `WaitForDecisionAsync` polling loop |
| Resolve role name → GUID | `GET /roleManagement/directory/roleDefinitions?$filter=displayName eq '{name}'` | Once at startup; cached process-lifetime |

### 7.2 Activation request payload

```json
{
  "action": "selfActivate",
  "principalId": "<caller-aad-object-id>",
  "roleDefinitionId": "<resolved-from-display-name>",
  "directoryScopeId": "/",
  "justification": "<from agent context, falls back to template>",
  "scheduleInfo": {
    "startDateTime": "<utcNow ISO 8601>",
    "expiration": { "type": "afterDuration", "duration": "PT15M" }
  }
}
```

`PT15M` is the ISO 8601 serialisation of `ApprovalSpec.GrantDuration`.
PIM policy can clamp to a shorter max — we surface that clamping in
the audit entry rather than swallowing it.

### 7.3 PIM status → ApprovalState mapping

| PIM `status` | Maps to |
|---|---|
| `Provisioned`, `PendingProvisioning` (with active schedule) | `Active(expiresAt)` |
| `PendingApproval`, `Granted`, `PendingScheduleCreation` | `Pending(requestId, portalUrl)` |
| `Denied`, `Failed`, `Revoked`, `Canceled`, `AdminApproved-but-Failed` | `Denied(reason, deniedAt)` |
| Schedule expired (past `endDateTime`) | `Denied("expired")` |

### 7.4 Caller identity mapping

`ISecurityContext.Id` → Entra `principalId`. Two pathways:

1. **Recommended:** operators populate `ISecurityContext.Id` with the
   AAD object ID directly. No Graph lookup needed.
2. **Fallback:** if `Id` looks like a UPN (`alice@contoso.com`), the
   store does one `GET /users/{UPN}` and caches the resolution.

Lookup failures surface as `Denied("caller principal not found in
Entra")` — never crashes the host.

### 7.5 Polling + retry

```
Initial wait    : 1 s
Backoff         : ×2 capped at 30 s, with ±20% jitter
Total bound     : ApprovalSpec.WaitTimeout (default 5 min)
On 429          : honour Retry-After header, no double-counting against timeout
On 5xx          : same backoff schedule, count as continuing wait
On 401 / 403    : fail fast — "host needs RoleManagement.ReadWrite.Directory consent"
On network drop : two retries, then surface as a transient denial
```

### 7.6 Required Graph permissions

Host (whichever process runs `sentinel-hook` / `sentinel-mcp`) needs
**delegated or application** permissions:

- `RoleManagement.Read.Directory` — read paths
- `RoleManagement.ReadWrite.Directory` — POST activation requests

Both require **admin consent** in Entra. One-time deployment step;
documented as a copy-paste command using `az` or `gh`.

### 7.7 Approval URL construction

```
https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles/RequestId/{requestId}
```

PIM has a deep-link view to a specific request. Falls back to the
generic PIM landing page if the deep-link view changes shape.

### 7.8 Token acquisition

`Azure.Identity.ChainedTokenCredential` with the standard chain:

```
ManagedIdentityCredential       — Azure VM / App Service / AKS workload identity
WorkloadIdentityCredential      — federated identity for k8s outside Azure
EnvironmentCredential           — AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
AzureCliCredential              — dev (az login)
```

No Sentinel-specific auth env vars. Tokens cached in-process; ~60 s
before expiry triggers a silent refresh.

## 8. Host integration patterns

Three host shapes, three async-tolerance levels:

| Host | Lifetime | Wait support | Approval pattern |
|---|---|---|---|
| `IChatClient` middleware (in-process) | long-lived | yes — `await Task<ApprovalDecision>` natively | block on the call until decided/timeout |
| `sentinel-mcp` proxy (stdio) | long-lived per host session | yes, within one `tools/call` round-trip | block the response for up to N seconds, return on decision |
| `sentinel-hook` / `sentinel-copilot-hook` | per-invocation, exits in milliseconds | **no** — host expects sync exit code 0 or 2 | **deny-with-receipt:** exit 2, return request ID, user approves out-of-band, retries the tool call |

The CLI deny-and-retry pattern is the right semantics — same as `sudo`
or PIM portal activation. Power users grok it instantly.

For `sentinel-mcp`, an env var configures the wait behaviour:

```
SENTINEL_MCP_APPROVAL_WAIT_SEC=300   # block for up to 5 mins (default 0 = fail fast)
```

## 9. CLI configuration surface

### 9.1 Single config file + env-only secrets

`approvals.json`:

```json
{
  "backend": "entra-pim",
  "tenantId": "${AZURE_TENANT_ID}",
  "defaultGrantMinutes": 15,
  "defaultJustificationTemplate": "AI agent invocation: {tool}",
  "includeConversationContext": true,
  "tools": {
    "delete_database": { "role": "Database Administrator", "grantMinutes": 30 },
    "deploy_*":        { "role": "Deploy Approver" },
    "send_payment":    { "role": "Finance Officer", "requireJustification": true }
  }
}
```

Env vars carry only **backend selection + Azure SDK credentials**
(via `ChainedTokenCredential`):

```bash
SENTINEL_APPROVAL_CONFIG=/etc/sentinel/approvals.json
# auth follows ChainedTokenCredential — managed identity preferred,
# AZURE_* vars supported for dev
```

### 9.2 Justification flow

Default behaviour:

1. **Rich path:** read agent's previous user prompt and/or tool-call
   reasoning from the JSON the host passes us (Claude Code passes
   `tool_use_id` + reasoning context; Copilot passes the user's last
   message). Truncate to 1024 chars (PIM's limit).
2. **Fallback:** if the host doesn't supply context, use the template
   (`"AI agent invocation: {tool}"`).
3. **Privacy escape hatch:** `"includeConversationContext": false`
   in the config disables the rich path. Always uses template.

The rich path is what makes auditors happy six months after the fact;
the template is what makes the system not crash when the agent
context is missing.

### 9.3 Packaging — bundled CLI binary

The CLI tools (`sentinel-hook`, `sentinel-copilot-hook`,
`sentinel-mcp`) bundle every approval backend in a single binary.
Operators install once:

```bash
dotnet tool install -g AI.Sentinel.ClaudeCode.Cli
dotnet tool install -g AI.Sentinel.Copilot.Cli
dotnet tool install -g AI.Sentinel.Mcp.Cli
```

Backend selection at runtime via env (`SENTINEL_APPROVAL_BACKEND` or
the config file). Cost: ~5 MB extra disk for the Graph SDK even
when the user only needs InMemory. Acceptable — these are dev tools.

Plugin discovery (AssemblyLoadContext) and separate per-backend
binaries (`sentinel-hook-pim`) were both considered and rejected.
Plugin loading is brittle in dotnet tools (version skew, debugger
pain); separate binaries multiply install steps and config files.

### 9.4 Sample Claude Code `settings.json`

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "command": "sentinel-hook pre-tool-use",
        "env": {
          "SENTINEL_APPROVAL_CONFIG": "${userHome}/.config/sentinel/approvals.json",
          "AZURE_TENANT_ID": "${env:AZURE_TENANT_ID}"
        }
      }
    ]
  }
}
```

Auth secrets in env (especially `AZURE_CLIENT_SECRET`) are a footgun.
For enterprise we recommend **federated workload identity** (no
secret in env) or **managed identity** when the agent runs on Azure.
Both are detected automatically by `ChainedTokenCredential`.

## 10. Optionality + back-compat

### 10.1 Layers of optionality

- **Package-level:** don't reference `AI.Sentinel.Approvals.*` → no
  new code in your app.
- **Configuration-level:** reference the package but never call
  `opts.RequireApproval(...)` → all the new code is dead.
- **API-level:** `RequireToolPolicy(...)` keeps its current Allow/Deny
  binary semantics. New tier rides on a separate verb.
- **Existing custom `IAuthorizationPolicy` impls:** unchanged.
  Continue to return bool; the `RequireApproval` tier is a separate
  concept on top.

### 10.2 The one source impact

Adding `RequireApproval` to the sealed `AuthorizationDecision`
hierarchy is binary-compatible but exhaustive switches surface
compiler warning **CS8509** on rebuild. Two helpers to dodge:

```csharp
// "I don't care about approvals, treat them as deny":
public static AuthorizationDecision AsBinary(this AuthorizationDecision d) =>
    d is RequireApproval r ? new Deny(r.PolicyName, "approval required") : d;

// "Just tell me yes/no":
public static bool IsAllowed(this AuthorizationDecision d) => d is Allow;
```

Existing callers add `_ => false` (or use the helpers) — one line.
Hosts that DO care (chat-client middleware, MCP proxy, CLI hooks)
write the explicit `RequireApproval` arm.

### 10.3 Startup-time guardrail

Wiring `opts.RequireApproval(...)` without a registered
`IApprovalStore` throws at DI build time:

> `opts.RequireApproval("delete_database", ...)` configured but no
> IApprovalStore registered. Add one of:
> AddSentinelInMemoryApprovalStore(), AddSentinelEntraPimApprovalStore(),
> or AddSentinelSqliteApprovalStore().

Better than a runtime surprise on first tool call.

## 11. Staging plan

| Stage | Scope | Effort |
|---|---|---|
| **1** | Core: `RequireApproval` decision tier + `IApprovalStore` + `IApprovalAdmin` + `InMemoryApprovalStore` + `IChatClient` middleware integration + binding registration verb + back-compat helpers | ~1 wk |
| **2** | `AI.Sentinel.Approvals.EntraPim` package: `EntraPimApprovalStore`, Graph client, role-name resolution, polling loop, ChainedTokenCredential integration | ~1-2 wk |
| **3** | `AI.Sentinel.Approvals.Sqlite` package: `SqliteApprovalStore` for non-enterprise CLI deployments | ~3 days |
| **4** | Dashboard pending-approvals page + Approve/Deny UI (gated on `IApprovalAdmin`); for `EntraPim`, fallback to "Approve at PIM portal" link | ~1 wk |
| **5** | CLI integration: `sentinel-hook`, `sentinel-copilot-hook`, `sentinel-mcp` config-file loader + backend selection + deny-with-receipt formatting + `WaitForDecisionAsync` for the proxy | ~1 wk |
| **6** | Documentation: dedicated docs site section, sample apps, audit-trail integration notes | ~3 days |

**Stages 1+2** deliver enterprise value end-to-end. Stages 3-5 round
out non-enterprise + CLI deployments.

## 12. Open questions

- **Multi-approver/quorum approval** — PIM supports it natively. For
  InMemory/SQLite, decide later whether a single approver is enough
  (probably yes for v1).
- **Standby approver / approval delegation** — PIM has eligibility
  schedules; our InMemory/SQLite probably don't need this for v1.
- **Audit forwarding for PIM activations** — when PIM logs an
  activation, AI.Sentinel's audit store also gets an entry. Decide
  whether to dedupe these (we have the Graph activation log AND our
  local entry) or treat them as parallel evidence.
- **Concurrent activation requests across multiple processes** —
  two CLI invocations at the same moment both POST to Graph. PIM
  creates two requests. Wasteful but harmless. Document as a known
  edge case.
- **Approval revocation** — operator approves, then revokes within
  the grant window. Both PIM and our internal stores can express this;
  the audit entry must reflect the revocation cleanly.

## 13. Out of scope (deferred to follow-ups)

- Slack/Teams card-based approval (out-of-process, separate backend
  package — `AI.Sentinel.Approvals.Slack`)
- ServiceNow change-management integration
- Approval policies bound to specific arg shapes (e.g., "approve
  `delete_database` only if `table != 'users'` automatically") —
  v2 territory.
- Per-tenant approval store routing (tied to per-pipeline Phase B)
