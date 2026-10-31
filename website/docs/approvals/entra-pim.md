---
sidebar_position: 4
title: Entra PIM backend
---

# Microsoft Entra PIM backend

Routes approvals through **Microsoft Entra Privileged Identity Management**. Approvers use the **native Entra PIM portal** they already know — the same UX that gates `Global Administrator` activation. AI.Sentinel translates a tool-call approval request into a PIM role-activation request, polls for the outcome, and resumes the conversation.

Ships in **`AI.Sentinel.Approvals.EntraPim`** and is bundled into all three CLIs.

## When to use it

- **Enterprise tenants** with Entra ID P2 and PIM already in production.
- **You want the audit trail in Azure AD**, not in your app database.
- **Approvers are already in Entra groups/roles** — no separate user list to maintain.

## Required Graph permissions

Admin-consent these on your app registration:

- `RoleManagement.Read.Directory`
- `RoleManagement.ReadWrite.Directory`

```bash
# Replace <APP-OBJECT-ID> with your service principal's object ID
az ad app permission admin-consent --id <APP-OBJECT-ID>
```

## Wiring

```csharp
using AI.Sentinel.Approvals.EntraPim;

services.AddSentinelEntraPimApprovalStore(opts =>
{
    opts.TenantId = "00000000-1111-2222-3333-444444444444";
    // Optional: defaults to system-assigned managed identity → workload identity
    //           → environment vars → Azure CLI. Override by registering a TokenCredential
    //           in DI before this call.
});

services.AddAISentinel(opts =>
{
    opts.RequireApproval("delete_database", spec =>
    {
        spec.GrantDuration = TimeSpan.FromMinutes(15);
        spec.BackendBinding = "Database Administrator";   // PIM role name
    });
});
```

`spec.BackendBinding` is the **PIM role name** (or role-template GUID) the approval activates. Approvers configured on that role in PIM get the request.

## CLI config

```json
{
  "backend": "entra-pim",
  "tenantId": "00000000-1111-2222-3333-444444444444",
  "defaultGrantMinutes": 15,
  "tools": {
    "delete_database": { "role": "Database Administrator" }
  }
}
```

A rule can carry [argument conditions](/docs/approvals/cli-config#argument-conditions), but `grantScope: "call"` is rejected with this backend, at config load, and in code when the tool-call guard is first resolved, because a PIM grant is a role activation and cannot be tied to arguments. The in-code check sees the store through AI.Sentinel's own wrappers only, the auditing and webhook wrappers. A decorator of your own around `EntraPimApprovalStore` hides the store from the check, so a call-scoped rule is then not rejected and its grant silently covers the whole role activation.

## Authentication chain

By default `AddSentinelEntraPimApprovalStore` builds a `ChainedTokenCredential`:

1. System-assigned managed identity (best for Azure-hosted apps)
2. Workload identity federation (AKS / Azure DevOps OIDC)
3. Environment variables (`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`)
4. Azure CLI (`az login` — dev-only fallback)

To override (e.g. inject a test credential), register a `TokenCredential` in DI **before** calling `AddSentinelEntraPimApprovalStore`.

## Polling and rate limits

- The store polls Graph for the request status with backoff + jitter (`PollInterval` default `1s`, `PollMaxBackoff` default `30s`, ±20% jitter). Tune both via `EntraPimOptions` if Graph rate limits become a concern at scale.
- Honors `Retry-After` on 429/503/504 responses.
- Reflective `ODataError` accessors keep the runtime decoupled from Graph SDK internals (AOT-safe — see [trim suppressions](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/src/AI.Sentinel.Approvals.EntraPim/MicrosoftGraphRoleClient.cs)).

## Repeated calls

While an activation request for the same caller and role is pending, a second call returns that request and creates no new one. If the lookup for a pending request cannot finish within 20 pages of results from Graph, the call is denied instead of risking a duplicate.

Because only a call that creates a request sends the [approval webhook](/docs/approvals/cli-config#notify-on-new-requests), the repeat call sends nothing.

## Approver UX

Approvers go to the **Entra PIM portal** → My approvals. The AI.Sentinel dashboard panel for an Entra-PIM-backed store shows pending requests as "actionable elsewhere" (the `IApprovalAdmin` interface is intentionally not implemented — approval state lives in Azure, not in your app).

## Caller identity

The caller's `ISecurityContext.Id` must be a **GUID** matching an Entra user's `objectId`. Non-GUID callers are rejected at request time (`ApprovalState.Denied` with reason). The agent runtime is responsible for setting `ISecurityContext.Id` to the upstream user's Entra object ID — typically pulled from the JWT `oid` claim.
