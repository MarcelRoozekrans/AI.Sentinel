# Approval webhook: notify when a request is created (#458)

## Intent

When `sentinel-hook`, `sentinel-copilot-hook` or `sentinel-mcp` creates an approval request, nobody is told. With
`SENTINEL_MCP_APPROVAL_WAIT_SEC` the agent sits idle until someone happens to open the dashboard; with a hook the user
gets a receipt but the approver gets nothing. An optional webhook in the CLI approval config tells the approver the
moment a **new** request exists, so it reaches ntfy, Slack or a small relay without a custom host.

## Goals

- `notifyUrl` in the approval config file. When a request is created, the CLI POSTs one JSON payload to it.
- One notification per request: a concurrent or later caller that reuses a pending request does not notify again, also
  when the callers are separate hook processes sharing a SQLite file.
- A failed POST is logged and never changes the decision or the state returned to the caller.
- No tool arguments in the payload by default. `notifyIncludeArgs: true` sends them redacted.
- `notifyHeaders` for an auth header, such as a bearer token for ntfy or a relay.
- Works for every backend: `in-memory`, `sqlite`, `entra-pim`.
- The Entra PIM store stops creating a second activation request while one is pending, so the rule above holds there.

## Non-goals

- A notification API for library hosts that call `AddAISentinel`. Marcel chose CLIs only. The one public addition is
  `ApprovalState.Pending.IsNew`, which the feature needs from the stores in other packages.
- Notifications on approval, denial, expiry or timeout.
- Retries or a delivery queue. A missed notification is a missed notification; the request is still in the store.
- Per-target payload formats, such as a `notifyFormat` switch.
- Per-tool notify URLs.

## Anti-goals

- A webhook outage that blocks, denies or allows a call, or delays it by more than the timeout.
- Raw argument values, header values or URL secrets in logs, hook output or the payload.
- Two notifications for one request.

## Constraints found in the code

- `IApprovalStore.EnsureRequestAsync` is idempotent and returns the same `ApprovalState.Pending` for a fresh request and a
  reused one. Only the store knows it inserted: the SQLite store inserts under `BEGIN IMMEDIATE`
  (`SqliteApprovalStore.cs`, the `InsertPendingAsync` path), the in-memory store when it adds an entry, the Entra PIM
  store after `CreateActivationRequestAsync`.
- A hook is a short-lived process that prints its receipt and exits. A background POST would be killed with it, so the
  POST has to complete, or time out, before `EnsureRequestAsync` returns.
- `ApprovalConfigLoader` already expands `${VAR}` over the whole file before parsing, so the new fields get it for free.
- There is no `/approvals/<id>` page. The approvals panel exists only in a host that calls `MapAISentinel`, and #453 adds
  it to `sentinel dashboard`. The payload therefore links to the dashboard base URL, not a per-request page.
- The CLIs are AOT-published since #456: JSON goes through a source-generated `JsonSerializerContext`, as
  `AlertJsonContext` does for `WebhookAlertSink`.

## Approaches

**A. The store reports a new request (chosen).** `ApprovalState.Pending` gets `public bool IsNew { get; init; }`. The
three built-in stores set it to `true` only on the `EnsureRequestAsync` call that created the request. An internal
decorator posts when it sees `IsNew`. Only the process that won the SQLite insert sees `true`, so it holds across
processes. Cost: one additive public property; a third-party store that never sets it never notifies.

**B. A `notified_at` column in SQLite.** The decorator claims the row in a transaction, then posts. SQLite only;
in-memory and Entra PIM would need their own variants, and it needs a schema migration. It would allow a retry on the
next call.

Rejected without a vote: guessing "new" from `RequestedAt` close to now. Two callers within the window both notify, which
is exactly the case the issue excludes.

Marcel picked A on 2026-10-31.

## Design

### Public API

```csharp
public sealed record Pending(string RequestId, string ApprovalUrl, DateTimeOffset RequestedAt) : ApprovalState
{
    /// true only on the EnsureRequestAsync call that created this request.
    public bool IsNew { get; init; }
}
```

`WaitForDecisionAsync` never returns `IsNew = true`. The XML doc says that stores which do not set it get no
notifications. Record equality now includes `IsNew`; no caller compares `Pending` values today, and the builder confirms
that.

### Stores

A request created after the previous one was denied or expired is a new request and gets `IsNew = true`, so a
denied-then-retried call notifies again. Builder's call, settled in the review: the approver has a fresh request to
decide.

- `InMemoryApprovalStore`: `IsNew = true` on the call that adds the entry.
- `SqliteApprovalStore`: `IsNew = true` on the insert path only; the dedupe path returns the row's state as today.
- `EntraPimApprovalStore`: `IsNew = true` on the `Pending` built right after `CreateActivationRequestAsync`. The polling
  and status-mapping paths leave it `false`.

### Entra PIM dedupe (fixed in this PR)

Today `EntraPimApprovalStore.EnsureRequestAsync` checks for an active assignment and eligibility, then always POSTs a
new activation request. It never looks for one already pending, which breaks the `IApprovalStore` contract that repeated
calls during a pending request create no duplicates. Depending on Graph, a retried hook gets a generic `Denied` or a
second PIM request. Marcel chose on 2026-10-31 to fix it here: between the eligibility check and the create, the store
reads `roleAssignmentScheduleRequests` for the same principal and role with a pending status (the statuses
`IsPendingStatus` already knows) and, when one exists, returns it as `Pending` with `IsNew = false` and its own
`RequestedAt`. Only when none exists does it create. A Graph error on that read maps through `ClassifyGraphError` like
the other reads. Tests cover: pending found, so no POST and `IsNew` false; none found, so POST and `IsNew` true; the read
failing.

### Config

New optional root keys in the approval config, all parsed and validated by `ApprovalConfigLoader` and carried on
`ApprovalConfig`:

| Key | Type | Default | Validation |
|---|---|---|---|
| `notifyUrl` | string | none, which turns the feature off | absolute `http` or `https` URI |
| `notifyHeaders` | object of string to string | empty | only with `notifyUrl`; values must be strings; header names valid for `HttpRequestHeaders`, no `Content-Type` or `Content-Length` |
| `notifyIncludeArgs` | bool | `false` | only with `notifyUrl` |
| `dashboardUrl` | string | none | absolute `http` or `https` URI |

`notifyHeaders` or `notifyIncludeArgs` without `notifyUrl` fails the load with a message naming the key, in the style the
loader already uses. `dashboardUrl` is allowed on its own; it is only read by the notifier today.

### Payload

`POST notifyUrl`, `Content-Type: application/json`:

```json
{
  "text": "Approval needed: Bash for alice (approval:Bash). https://dash.example.com",
  "requestId": "req-…",
  "tool": "Bash",
  "callerId": "alice",
  "policy": "approval:Bash",
  "requestedAt": "2026-10-31T12:00:00+00:00",
  "approvalUrl": "sentinel://approve/req-…",
  "dashboardUrl": "https://dash.example.com",
  "args": { "command": "curl -H 'Authorization: [SECRET_1_k3f9x2]' …" }
}
```

- `text` makes a Slack incoming webhook work as is; Slack ignores the other fields. The link in `text` is `dashboardUrl`
  when set, otherwise `approvalUrl` when it is `http` or `https`, such as the PIM portal URL, otherwise no link.
- `approvalUrl` is the store's `Pending.ApprovalUrl`, sent as is.
- `dashboardUrl` is the config value, omitted when not set.
- `args` is present only with `notifyIncludeArgs: true`.

### Argument redaction

With `notifyIncludeArgs`, the notifier always runs a fresh `RedactionSession` over a `CredentialExposureDetector` and a
`PiiLeakageDetector`, whatever the CLI's other redaction settings are, and sends `RedactJsonValues(args)`. Argument names
stay, values are replaced by placeholders, and the originals never leave the process. Marcel chose both detectors on
2026-10-31.

### Notifier

An internal `NotifyingApprovalStore` decorator in core:

- `EnsureRequestAsync`: calls the inner store; when the result is `Pending { IsNew: true }`, it sends the payload and then
  returns the inner result unchanged. Any other result passes straight through.
- `WaitForDecisionAsync` passes straight through.
- The POST is awaited with a 3 s timeout, fixed. That fits well inside the host hook timeouts, 60 s by default for
  Claude Code, and it only applies on the call that creates a request, which is blocked or waiting anyway. #537 concerns
  the review timeout, not this one. A non-2xx status, an exception or the timeout is logged as a warning
  that names the endpoint through `SafeHttp.Describe` and the request id, never header values or the payload. Nothing is
  thrown and no retry happens.
- A cancelled caller token cancels the POST; that is not logged as a webhook failure.
- The response body is not read.
- It implements `IApprovalAdmin` exactly when the inner store does, as `AuditingApprovalStore` and
  `AuditingApprovalAdminStore` do.

### DI placement

The notifier wraps the inner store **inside** `AuditingApprovalStore`, at the point where
`ApprovalStoreAuditing.Wrap` receives the inner store, so every resolved `IApprovalStore` and `IApprovalAdmin` goes
through it. Code that unwraps to the inner store, `RejectCallScopedGrantsOnRoleActivationStore` today, must see through
it: both wrappers implement a small internal `IApprovalStoreDecorator { IApprovalStore Inner { get; } }`, and the unwrap
follows that chain until it reaches a store that is not a decorator. A test asserts that a `grantScope: call` rule is
still rejected with backend `entra-pim` when `notifyUrl` is set. In-memory, which `AddAISentinel` registers itself, goes
through the same path.

### CLI wiring

`sentinel-hook`, `sentinel-copilot-hook` and `sentinel-mcp` wrap their approval store in `NotifyingApprovalStore` when
the loaded config has a `notifyUrl`. The wiring goes through one shared helper in core next to `ApprovalBackendSelector`,
so the three CLIs cannot drift. Hook processes are short-lived; because the POST is awaited inside
`EnsureRequestAsync`, it is done before the hook prints its receipt and exits.

### Docs

`website/docs/approvals/cli-config.md` gets the four keys, the payload, a Slack and an ntfy example, and the note that
the link points at the dashboard base URL until #453 adds per-request pages. The `ApprovalState.Pending.IsNew` XML doc
covers third-party stores.

### Release

Additive: `feat(approvals): …`, a minor bump on top of whatever #553 makes the next version.

## Tests

- Each store: `IsNew` is `true` on the creating call and `false` on a reuse, a re-read and in `WaitForDecisionAsync`.
  For SQLite, two store instances on one file: exactly one sees `true`.
- Loader: each key parses; each invalid value and each orphan key fails with its message; `${VAR}` expands in
  `notifyUrl` and in header values.
- Notifier, with a fake `HttpMessageHandler`: one POST for a new request, none for a reuse; payload shape; `text` link
  choice; headers sent; args absent by default and redacted when on; a 500, an exception and a timeout each return the
  inner state unchanged and log without header values; a cancelled token cancels.
- CLI: a config with `notifyUrl` wraps the store, one without leaves it as is.

## Left to the builder

- Where the `HttpClient` lives, shared static or per notifier, as long as the timeout is per request.
- The exact log category and message wording.
- How the detectors are constructed for the redaction session, given their constructors.
