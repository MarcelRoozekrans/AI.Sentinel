---
sidebar_position: 1
title: Overview
---

# Approval workflows overview

Some tool calls are too consequential to gate behind allow/deny alone — `delete_database`, `send_payment`, `rotate_secrets`. AI.Sentinel's approval workflow lets you require a **human approval out-of-band** for matched tool calls, then resume the conversation when the approval lands.

## When to use this vs. plain authorization

| You want... | Use |
|---|---|
| Allow/deny based on caller identity / role | [`IAuthorizationPolicy`](/docs/authorization/policies) |
| Allow/deny based on caller identity, AND a human approves first | This (RequireApproval) |

`RequireApproval` is **additive** — your existing `RequireToolPolicy(...)` bindings are unchanged. The same tool can have both: e.g. authorize "is this caller in the DBA group?" and *then* require a separate approver to sign off.

## The lifecycle

1. **Tool call hits the guard** — middleware (`AuthorizationChatClient`) or CLI hook routes through `IToolCallGuard`.
2. **Guard returns `RequireApprovalDecision`** — carries a `RequestId`, `ApprovalUrl`, and `WaitTimeout`.
3. **Approval pends** — the configured `IApprovalStore` (InMemory / SQLite / Entra PIM) holds the request until an approver settles it.
4. **Caller observes the outcome**:
   - **In-process middleware**: blocks via `WaitForDecisionAsync`, then re-evaluates the guard.
   - **Hook CLIs** (`sentinel-hook`, `sentinel-copilot-hook`): emits a deny-with-receipt, the user approves out-of-band and retries the prompt.
   - **MCP proxy**: wait-and-block when `SENTINEL_MCP_APPROVAL_WAIT_SEC` is set; fail-fast otherwise.

## The three backends

| Backend | Persistence | Approver experience | Best for |
|---|---|---|---|
| [In-memory](/docs/approvals/in-memory) | Process lifetime | Dashboard | Single-process apps; dev/demo |
| [SQLite](/docs/approvals/sqlite) | File on disk | Dashboard | CLI deployments; multi-process on one host |
| [Entra PIM](/docs/approvals/entra-pim) | Azure AD | Native PIM portal | Enterprise tenants with PIM already in place |

Backends are **exclusive** — one `IApprovalStore` per process. Switching is a config change; no code change.

## Wiring in code

Add a `RequireApproval` binding alongside your existing severity/policy config:

```csharp
services.AddAISentinel(opts =>
{
    opts.OnHigh = SentinelAction.Quarantine;

    opts.RequireApproval("delete_database", spec =>
    {
        spec.GrantDuration = TimeSpan.FromMinutes(15);
        spec.RequireJustification = true;
        spec.BackendBinding = "DBA";   // role name passed to the backend
    });
});
```

For CLIs (where source-edits aren't an option), use a [config file](/docs/approvals/cli-config) instead.

## Next steps

- Pick a backend: [in-memory](/docs/approvals/in-memory), [SQLite](/docs/approvals/sqlite), or [Entra PIM](/docs/approvals/entra-pim).
- For CLI hosts: [config file reference](/docs/approvals/cli-config).
- Approver UX: [pending-approvals dashboard panel](/docs/approvals/dashboard).
