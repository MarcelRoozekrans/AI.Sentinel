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

## Audit trail

When an `IAuditStore` is registered, every approval decision is written to the hash-chained audit log as an informational entry with policy code `APPROVED`, `DENIED`, `EXPIRED` or `TIMED_OUT`. The entry names the policy, the tool and the request id, and never the arguments, the approver's note or any caller or approver id. The `IApprovalStore` and `IApprovalAdmin` that DI hands out for the built-in backends, and for a store registered with `AddSentinelApprovalStore`, are an auditing wrapper over the store, so a decision is recorded wherever it is taken: in the tool-call guard, `UseToolCallAuthorization`, the dashboard panel, the MCP proxy, or your own approval UI resolving either interface from DI. This holds in any registration order, and the wrapper writes to whichever `IAuditStore` is registered last. A backend still goes before an `AddAISentinel` that has `RequireApproval` bindings, as the [SQLite page](/docs/approvals/sqlite) explains. All of these share one wrapper, so a decision is written once.

- **The concrete store is not audited.** Resolving `SqliteApprovalStore` by its own type returns the store itself, and a decision taken through it is not recorded. Resolve `IApprovalStore` or `IApprovalAdmin` instead, and don't cast either to a concrete store type: the cast fails while an audit store is registered.
- **A custom store** is audited the same way when you register it with `AddSentinelApprovalStore`, as [Writing your own store](#writing-your-own-store) shows. One registered straight as `IApprovalStore` with `AddSingleton` is resolved from DI unwrapped: AI.Sentinel's own surfaces still record the decisions they take through it, but a decision your code takes through the `IApprovalStore` it resolves is not recorded. When such a store replaces the built-in in-memory store, the `IApprovalAdmin` you resolve is still an audited wrapper over it, so decisions taken through that interface are recorded.
- **Keyed DI services.** The store itself is registered as a keyed singleton under a private key, and `IApprovalStore` and `IApprovalAdmin` are factories over it. `RemoveAll<IApprovalStore>()` removes the factory, and registering another backend afterwards replaces the rest. A third-party container must support keyed services, as Microsoft.Extensions.DependencyInjection 8 and later does.
- **Without an `IAuditStore`** DI hands out the store unwrapped. The unnamed `AddAISentinel` always registers an in-memory audit store, so this happens only when you register named pipelines alone or the backend without `AddAISentinel`.

With Entra PIM the decision is made in PIM, so AI.Sentinel records only what it observes:

- **Denials**: a PIM denial is recorded only by a process that waits for the decision, such as the in-process chat client or the MCP proxy with `SENTINEL_MCP_APPROVAL_WAIT_SEC` set. The hook CLIs and the fail-fast MCP proxy never wait, so they never observe a denial: the caller's next attempt simply opens a new request. A Graph error while waiting is not a decision and is not recorded.
- **Approvals in the hook CLIs**: each hook invocation is a new process that remembers nothing. The first time a process sees a PIM grant, it looks in the audit store for an `APPROVED` entry of that request, written since the grant started, and records the approval only when there is none. A grant is therefore normally recorded once across processes that share the audit store; two hook processes that see the grant at the same moment can both record it. If that lookup fails, the approval is recorded anyway, since a duplicate entry is better than a missing decision; the [compliance report](/docs/compliance-report) counts each request once per outcome either way.

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

Policies and approval requests see the real argument values, not [redaction](/docs/redaction) placeholders, so an approver can judge the actual call.

## Writing your own store

A custom backend implements `IApprovalStore`, and `IApprovalAdmin` as well when approvers decide in the [dashboard panel](/docs/approvals/dashboard). Register it with `AddSentinelApprovalStore`, which the built-in backends use too, so the decisions taken through it are [audited](#audit-trail) wherever the store is resolved:

```csharp
services.AddSentinelApprovalStore(sp => new MyApprovalStore(sp.GetRequiredService<MyApprovalOptions>()));
```

It registers `IApprovalStore`, and `IApprovalAdmin` when your type implements it, and throws if an `IApprovalStore` is already registered. Register it before an `AddAISentinel` that has `RequireApproval` bindings, or that call registers the in-memory store first.

Set `RequestId` on every `ApprovalState.Active` and `ApprovalState.Denied` you return whenever the store knows the request, as the built-in stores do. [Approval decisions](#audit-trail) in the audit log are recorded under that id.

For a store that implements `IApprovalAdmin`, AI.Sentinel records `ApproveAsync` and `DenyAsync` itself, from the request id they are called with. For a store without it, whose decisions are made elsewhere as with Entra PIM, AI.Sentinel records what the store returns:

- **A `Denied` without a `RequestId` is not recorded as a decision.** AI.Sentinel treats it as a denial that belongs to no request, such as a backend error while polling, so a real denial returned without an id is missing from the audit log.
- **An `Active` without a `RequestId`** is recorded under the id this process waited on or saw pending. A process that saw neither, such as a hook invocation after an earlier one opened the request, records no `APPROVED` entry.

For either kind of store, an expired grant is returned as a `Denied` with the reason `"expired"` and recorded as `EXPIRED`. Without a `RequestId` that entry names the request this process remembers for the caller and policy, or `unknown`.

## Next steps

- Pick a backend: [in-memory](/docs/approvals/in-memory), [SQLite](/docs/approvals/sqlite), or [Entra PIM](/docs/approvals/entra-pim).
- For CLI hosts: [config file reference](/docs/approvals/cli-config).
- Approver UX: [pending-approvals dashboard panel](/docs/approvals/dashboard).
