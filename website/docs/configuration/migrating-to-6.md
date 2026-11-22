---
sidebar_position: 6
title: Migrating to 6.0
---

# Migrating to 6.0

6.0 drops the net8.0 and net9.0 targets and changes what `IApprovalAdmin.ApproveAsync` and `DenyAsync` return.

## .NET 10 or later

Every package now targets net10.0 and net11.0 only. Its ZeroAlloc dependencies dropped net8.0 and net9.0 in the same way.

**What breaks:** a project that targets net8.0 or net9.0 can no longer restore AI.Sentinel 6.x.

**What to do:** move the project to net10.0 or later, or stay on AI.Sentinel 5.x. The hook and MCP CLIs already needed the .NET 10 SDK since 5.0; nothing changes for them.

## `IApprovalAdmin` decisions report their outcome

`ApproveAsync` and `DenyAsync` return `ValueTask<ApprovalDecisionOutcome>` instead of `ValueTask`:

| Value | Meaning |
|---|---|
| `Applied` | The request was pending and this call settled it. |
| `AlreadySettled` | The request exists but was already approved or denied, for example by a concurrent approver. Nothing changed. |
| `NotFound` | The store holds no request with this id. |

The dashboard answers `POST /api/approvals/{id}/approve` and `/deny` with `200` for `Applied`, `409 Conflict` for `AlreadySettled` and `404 Not Found` for `NotFound`. Before 6.0 a second approver who raced the first could get `200` for a decision that never took effect, and an unknown id got `409`.

**What breaks:** a custom store that implements `IApprovalAdmin` no longer compiles.

**What to do:** return the outcome. Check that the request is pending and settle it in one atomic step, so that of two concurrent calls only one returns `Applied`:

```csharp
public async ValueTask<ApprovalDecisionOutcome> ApproveAsync(
    string requestId, string approverId, string? note, CancellationToken ct)
{
    // For example UPDATE ... SET status = 'Active' WHERE id = @id AND status = 'Pending'
    var changed = await _db.ApproveIfPendingAsync(requestId, approverId, note, ct);
    if (changed) return ApprovalDecisionOutcome.Applied;
    return await _db.ExistsAsync(requestId, ct)
        ? ApprovalDecisionOutcome.AlreadySettled
        : ApprovalDecisionOutcome.NotFound;
}
```

AI.Sentinel writes the `APPROVED` or `DENIED` audit entry only for a call that returns `Applied`.

Callers that only await `ApproveAsync` or `DenyAsync` keep compiling; read the result when you need to know whether the call took effect.
