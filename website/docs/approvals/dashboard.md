---
sidebar_position: 5
title: Dashboard panel
---

# Pending-approvals dashboard panel

The AI.Sentinel dashboard ships a **Pending Approvals** panel alongside the live event feed and stats panels. Operators approve or deny tool-call requests from the same page they monitor severity events.

## Mounting

The panel is part of `MapAISentinel(...)` — no additional setup beyond mounting the dashboard:

```csharp
var app = builder.Build();
app.MapAISentinel("/ai-sentinel")
   .RequireAuthorization("Operators");
```

## What it shows

The panel polls `GET /ai-sentinel/api/approvals` every 3s via HTMX and renders rows for every `Active` request returned by the registered `IApprovalStore` (when it implements `IApprovalAdmin`):

| Column | Source |
|---|---|
| Time | `requestedAt` |
| Caller | `callerId` (truncated for display) |
| Tool | `toolName` |
| Actions | Approve / Deny buttons |

Approve/Deny POST to `/api/approvals/{id}/approve` or `/api/approvals/{id}/deny`. Successful POST returns `200 OK` with an empty `text/html` body — HTMX swaps the row out via `outerHTML` (with a 250ms fade transition driven by the `htmx-swapping` CSS class).

## When the store doesn't implement `IApprovalAdmin`

Some backends — notably **Entra PIM** — keep approval state in an external system. For those stores, `/api/approvals` returns a single `<tr class="approvals-external">` row with the message:

> Approvals are managed externally (Entra PIM portal). Use the Azure portal to approve or deny.

This isn't an error — it's the intended UX. Routing approvals through PIM means PIM owns the surface, not your app. Approvers act in the [Azure portal → My approvals](https://portal.azure.com/#blade/Microsoft_Azure_PIMCommon/CommonMenuBlade/quickStart).

## Authentication

The panel inherits whatever authorization you put on the dashboard route group. The Approve/Deny POST handlers **fail closed** with `401 Unauthorized` if `HttpContext.User.Identity?.IsAuthenticated` is false — even on un-protected routes — so an accidental misconfiguration can't end up letting anonymous users approve dangerous tool calls.

The approver's identity (whatever `User.Identity.Name` resolves to) is recorded as the `approverId` on the settled request.

## XSS hardening

User-provided fields (`callerId`, `toolName`, justification text) flow through `HtmlEncoder.Default.Encode` and `Uri.EscapeDataString` before being rendered or used in URLs. The `'` character is escaped to `&#39;` in addition to standard encoding.

## Mobile layout

Below 600px viewport width, the panel collapses to single-column with horizontal table scroll; below 480px, the (diagnostic-only) hash column is hidden — operators triage on Time / Caller / Tool / Actions.

## Programmatic access

If you'd rather drive approvals from your own UI:

- `GET /ai-sentinel/api/approvals` returns the same data as the panel's HTMX poll.
- `POST /ai-sentinel/api/approvals/{id}/approve` / `/deny` are the same endpoints the panel posts to.

Both are part of the [route group](/docs/getting-started/dashboard) and respect any `.RequireAuthorization(...)` you apply to it.
