---
sidebar_position: 2
title: In-memory backend
---

# In-memory approval store

The default backend. Holds pending approvals in a `ConcurrentDictionary` keyed by `RequestId`. Survives only as long as the process — when the host restarts, every pending request is lost.

## When to use it

- **Dev / demos** — fast feedback, no infrastructure.
- **Single long-lived process** that owns approvals end-to-end (e.g. ASP.NET Core host with the dashboard mounted).
- **Tests** — drop in `TimeProvider.System` substitute for deterministic timing.

Don't use it for CLI deployments (each invocation is a fresh process — see [SQLite](/docs/approvals/sqlite)).

## Wiring

InMemoryApprovalStore is **auto-registered** as `IApprovalStore` when any `RequireApproval(...)` binding is present and no other store is registered. No explicit DI call needed:

```csharp
services.AddAISentinel(opts =>
{
    opts.RequireApproval("delete_database", spec =>
    {
        spec.GrantDuration = TimeSpan.FromMinutes(15);
        spec.RequireJustification = true;
        spec.BackendBinding = "DBA";
    });
});
// InMemoryApprovalStore is registered automatically.
```

## Approver UX

Mount the [dashboard](/docs/approvals/dashboard) — operators approve/deny via the pending-approvals panel. The `IApprovalAdmin` interface (which `InMemoryApprovalStore` implements) is what powers the panel's POST endpoints.

## Behavior notes

- **Dedupe**: a second `EnsureRequestAsync` call with the same `(callerId, toolName)` while one is `Active` returns the existing request. After the request settles (Approved/Denied/Expired), the next call creates a fresh request.
- **Wait semantics**: `WaitForDecisionAsync` polls the in-memory state via `TaskCompletionSource` — wakes immediately when the approver acts, no polling latency.
- **Grant duration**: `ApprovalState.Active` holds the approval valid for `spec.GrantDuration` from approval time. After expiry, the next tool call creates a new request.

## Limits

- **No persistence** — process restart wipes all pending requests. Operators see them disappear from the dashboard; agents see their `WaitForDecisionAsync` call cancel with `OperationCanceledException` (host shutdown).
- **No cross-process visibility** — two processes each have their own dictionary; they can't see each other's pending requests.

For persistence across restarts on a single host: [SQLite](/docs/approvals/sqlite). For enterprise-scale, multi-tenant approval routing: [Entra PIM](/docs/approvals/entra-pim).
