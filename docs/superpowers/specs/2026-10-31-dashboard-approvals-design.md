# Dashboard approvals: approve from `sentinel dashboard` (#453)

## Intent

A CLI-only deployment (`sentinel-hook`, `sentinel-copilot-hook`, `sentinel-mcp` with the SQLite approval backend) writes
approval requests that no shipped UI can approve or deny. The Pending Approvals panel exists only in a custom ASP.NET
host that calls `MapAISentinel`. `sentinel dashboard` (AI.Sentinel.Cli) should become that UI: it mounts the panel over
the same approval store the CLIs write, gets the approver's identity from a forward-auth reverse proxy or, for a solo
developer, from the local OS user, and records each decision in the audit log like any other host does.

While at it, approvers get to see what they approve. Today a panel row shows only time, caller and tool; with
`grantScope: "call"` the approver signs off on arguments they cannot see. A per-request page shows them, and the #458
webhook text links to it.

## Goals

- `sentinel dashboard --approval-config <path>` loads the CLI approval config with the same `ApprovalConfigLoader` the
  hooks use. Without the flag, `SENTINEL_APPROVAL_CONFIG` is used when set. With a `sqlite` backend the panel lists the
  pending requests and Approve and Deny work.
- The approver's identity comes from exactly one of:
  - `--trusted-proxy <cidr>` (repeatable) with `--user-header <name>` (default `X-Auth-Request-User`): a request whose
    remote address is in a trusted range and that carries a valid header value is authenticated as that user;
  - `--local-approver`: a loopback request is authenticated as the OS user running the dashboard.
  Any other request is anonymous, and Approve and Deny keep failing closed with 401.
- `--bind <ip>` (default `127.0.0.1`). A non-loopback address is accepted only together with `--trusted-proxy`.
- With approvals enabled the audit file is opened writable and each decision made in the dashboard writes its
  `APPROVED` or `DENIED` entry, through the existing `AuditingApprovalAdminStore`. Without approvals the dashboard stays
  read-only, exactly as today.
- Approve and deny POSTs from another site are rejected (CSRF), in the shared handlers, so every `MapAISentinel` and
  `UseAISentinel` host gets the protection.
- A per-request page `<prefix>/approvals/{id}` shows tool, caller, policy, requested-at, justification and the
  arguments redacted with `CredentialExposureDetector` + `PiiLeakageDetector`, with Approve and Deny. Panel rows link to
  it. The page lives in the shared handlers, so custom hosts get it too.
- The #458 webhook `text` links to `<dashboardUrl>approvals/<id>` for the `sqlite` backend.

## Non-goals

- A public trusted-proxy authentication helper in `AI.Sentinel.AspNetCore` for custom hosts. They have the ASP.NET
  auth stack; add one later if someone asks.
- Authentication built into the dashboard itself: logins, sessions, OIDC. Identity comes from the proxy or the OS user.
- Approving Entra PIM requests from the dashboard. PIM owns that surface.
- Editing approval config, revoking active grants, or listing settled requests.
- TLS termination in the dashboard. The proxy does that.

## Anti-goals

- An approvals-enabled dashboard reachable from the network without an identity source.
- An approval recorded with a spoofed identity: a user header honoured from a request that did not come through a
  trusted proxy, or a local-approver identity given to a request that came through a proxy.
- A decision made in the dashboard that does not reach the audit log.
- Secrets from tool arguments in the browser, a proxy log or the page cache.
- A dashboard without approvals that writes to the audit file.

## Decisions (Marcel, 2026-10-31)

1. **Audit trail:** open the audit file writable only when approvals are enabled; the dashboard records decisions.
   Rejected: keeping it read-only with unaudited decisions, and making hooks record a grant when they next see it
   (denials would never be seen).
2. **Config source:** the approval config file (`--approval-config`, defaulting to `SENTINEL_APPROVAL_CONFIG`), not a
   bare `--approvals <db>` as #453 proposed, so the dashboard and the hooks share one source of truth.
3. **CSRF:** a Fetch Metadata / `Origin` check in the shared `DashboardHandlers`, shipped as a fix for all hosts.
   Rejected: CLI-only middleware, and antiforgery tokens (every existing host would need `AddAntiforgery`).
4. **Local mode:** opt-in `--local-approver`, loopback only, mutually exclusive with `--trusted-proxy`. Not implicit,
   because a reverse proxy added later on the same host would make every visitor look local.
5. **Detail page + webhook link**, with **redacted** arguments.
6. **Approach:** an internal middleware in AI.Sentinel.Cli sets `HttpContext.User` (see Approaches).

## Constraints found in the code

- `DashboardCommand` opens the audit file with `SqliteAuditStore.OpenReadOnly` and registers it as `IAuditStore`.
  `ApprovalStoreAuditing.Resolve` wraps the approval store in `AuditingApprovalAdminStore` whenever an `IAuditStore` is
  registered, and that wrapper's `ApproveAsync`/`DenyAsync` append to the audit store; on a read-only store the append
  throws. For an admin store (SQLite) the decision entry is written **only** by the process that approves: the hooks
  record nothing for it (`AuditingApprovalStore`, the `Admin is null` branches). So writable-with-approvals is required
  for decision 1, not optional.
- The writable `SqliteAuditStore` constructor creates the file and its directory, runs the schema initialisation, and
  starts a retention timer only when `RetentionPeriod` or `MaxDatabaseSizeBytes` is set. The dashboard must not create
  the file (keep the `File.Exists` check before opening) and must not run retention or a size cap: use default
  options, no `EnforceSizeCapOnOpen`. The hooks already write the file concurrently from separate processes, so the
  dashboard is one more writer of the same kind.
- `DashboardHandlers.ApproveAsync`/`DenyAsync` return 401 unless `ctx.User.Identity.IsAuthenticated`, and record
  `ctx.User.Identity.Name` as `approverId`. The middleware only has to set `ctx.User`.
- The panel is HTMX: `hx-post="api/approvals/{id}/approve"`, relative to the page under the prefix. htmx sends
  `HX-Request: true` and the browser adds `Sec-Fetch-Site` and `Origin`.
- `PendingRequest` carries `RequestId, CallerId, PolicyName, ToolName, Args (JsonElement), RequestedAt, Justification`.
  `IApprovalAdmin` has only `ListPendingAsync`, no lookup by id.
- `ApprovalNotification.Create` builds the link as `settings.DashboardUrl ?? (http approvalUrl)`. The CLIs read the
  config through `ApprovalConfigLoader`, which is `internal` in AI.Sentinel. AI.Sentinel has no `InternalsVisibleTo` for
  AI.Sentinel.Cli yet; add it, as the other CLIs have.
- AI.Sentinel.Cli references AI.Sentinel, AspNetCore and Sqlite, not `AI.Sentinel.Approvals.Sqlite`. It is not
  AOT-published (#456 covers the hook and MCP CLIs only).
- `website/docs/integrations/claude-code.md` says the dashboard "shows no approvals panel"; `approvals/dashboard.md` and
  `approvals/cli-config.md` describe the panel and `dashboardUrl`.

## Approaches

**A. Internal middleware in the CLI host (chosen).** A middleware ahead of `MapAISentinel` sets `HttpContext.User` to a
`ClaimsPrincipal` whose identity has a non-empty authentication type, from the trusted-proxy header or the OS user.
No public API, no auth-scheme plumbing, testable with `TestServer`.

**B. An ASP.NET `AuthenticationHandler` scheme in the CLI.** Same behaviour through `AddAuthentication`. More idiomatic,
but the options, scheme and challenge machinery buy nothing: the handlers already answer 401 themselves.

**C. A public trusted-proxy helper in `AI.Sentinel.AspNetCore`.** Reusable by custom hosts, but it is new public API to
document and support, and those hosts already have ASP.NET authentication. Deferred until asked for.

## Design

### Command line

```
sentinel dashboard [--db <audit.db>] [--port <n>] [--bind <ip>]
                   [--approval-config <path>]
                   [--trusted-proxy <cidr>]... [--user-header <name>]
                   [--local-approver]
```

Validation, all failing at parse time or before the server starts, with exit code 1 and a one-line reason on stderr:

- `--bind` must parse as an IP address. A non-loopback address (anything for which `IPAddress.IsLoopback` is false,
  including `0.0.0.0` and `::`) requires `--trusted-proxy`.
- `--trusted-proxy` must parse as a CIDR (`IPNetwork.TryParse`); a bare address means a single host (`/32`, `/128`).
- `--user-header` is only valid with `--trusted-proxy`, and must be a valid HTTP header token.
- `--local-approver` and `--trusted-proxy` are mutually exclusive. `--local-approver` requires a loopback `--bind`.
- `--trusted-proxy` or `--local-approver` without an approval store is accepted but prints a note that there is
  nothing to approve. (Builder may make this an error instead; the note is the softer default.)

Startup output gains one line after `Dashboard: <url>`, naming what approvals do in this run, for example
`Approvals: sqlite /var/lib/ai-sentinel/approvals.db, approver from X-Auth-Request-User via 10.0.0.0/24`, or
`Approvals: off`. It never prints header values or config secrets.

### Approval config

- `--approval-config <path>` wins; otherwise `SENTINEL_APPROVAL_CONFIG` when set and non-blank; otherwise approvals are
  off.
- The file is loaded with `ApprovalConfigLoader.Load`. A load error fails startup with the path and the loader's
  message (the loader never quotes URL values).
- Backend handling:
  - `sqlite`: open `SqliteApprovalStore` over `databasePath` and register it with
    `AddSentinelSqliteApprovalStore`, so DI hands out the auditing wrapper. Only `IApprovalAdmin` actions are used;
    the dashboard never creates requests and never wires the webhook notifier.
  - `entra-pim`: no store is built and no Graph call is made. The panel shows the existing "managed externally (Entra
    PIM portal)" row. How the handler learns this without a real store is the builder's call; a small internal marker
    the handler checks is fine, an `IApprovalStore` stub that throws is not.
  - `in-memory`: requests live inside each hook process, so the dashboard cannot see them. With an explicit
    `--approval-config` this is an error; from the environment variable it is a note and approvals are off.
  - `none`: approvals off, with a note.
- Approvals on means the audit file is opened writable (below). Approvals off means `OpenReadOnly`, as today.

### Audit file

With approvals on, the dashboard checks `File.Exists(db)` as today, then opens `new SqliteAuditStore(new
SqliteAuditStoreOptions { DatabasePath = db })`: no retention, no size cap. The hash-chain verification at startup is
unchanged. `RunningDashboard` disposes the approval store as well as the audit store.

### Identity middleware

Registered in the CLI host before `MapAISentinel`. For each request:

1. Trusted-proxy mode: if `RemoteIpAddress` (IPv4-mapped IPv6 normalised to IPv4) is inside one of the trusted
   networks, and the request has exactly one `--user-header` value that is non-empty after trimming, at most 256
   characters, and free of control characters, set `ctx.User` to a principal with `ClaimTypes.Name` = that value and
   authentication type `TrustedProxy`. Otherwise leave `ctx.User` anonymous.
2. Local-approver mode: if `RemoteIpAddress` is loopback, set `ctx.User` to `ClaimTypes.Name` = `Environment.UserName`,
   authentication type `LocalApprover`.
3. The user header is never honoured outside trusted-proxy mode, and `X-Forwarded-For` is never used for the trust
   decision: the decision is about the immediate peer, which is the proxy.

The middleware does not log header values.

### CSRF check (shared handlers)

In `DashboardHandlers.ApproveAsync` and `DenyAsync`, before the authentication check:

- `Sec-Fetch-Site` present and not `same-origin` or `none` → 403.
- Otherwise, `Origin` present and its scheme+host+port does not equal the request's own origin → 403. The request's
  origin is `Request.Scheme` + `Request.Host`; behind a proxy that rewrites `Host`, `Sec-Fetch-Site` decides first, so
  browsers that send Fetch Metadata are never refused because of a rewritten host. The builder decides whether an
  `Origin: null` is refused (recommended: yes).
- Neither header present (scripts, curl) → continue as today.

The 403 body is a plain sentence, like the 401's. Ship as `fix(dashboard):` so custom hosts see it in the changelog.

### Per-request page

`GET <prefix>/approvals/{id}` in both `MapAISentinel` and `UseAISentinel`:

- Resolves the store like the panel does. No store → 404 page "No approval store configured". Non-admin store → the
  "managed externally" message. Request id not among `ListPendingAsync` → 200 page "This request is no longer pending"
  (it was approved, denied, expired, or never existed; the page does not say which).
- Otherwise renders tool, caller, policy, requested-at (UTC, ISO 8601), justification, and the arguments as indented
  JSON after `RedactionSession([new CredentialExposureDetector(), new PiiLeakageDetector()]).RedactJsonValues(args)`,
  the same call the webhook uses. Every value is HTML-encoded.
- Approve and Deny buttons post to the existing endpoints. Deny has an optional reason field; empty falls back to
  `denied via dashboard`. After a decision the page shows the outcome instead of the buttons.
- `Cache-Control: no-store` on the page.
- It reuses the dashboard's stylesheet and htmx; links are relative to the prefix, like the index page.

Panel rows get a link on the tool name (or a "Details" link) to `approvals/{escaped id}`.

### Webhook link

For the `sqlite` backend, the webhook `text` link becomes `<dashboardUrl>approvals/<Uri.EscapeDataString(id)>`, and
the payload gains nothing else (`dashboardUrl` stays the configured value). For `entra-pim` and `in-memory` the link
logic is unchanged. `dashboardUrl` is documented as the dashboard page URL including its prefix, for example
`https://dash.example.com/ai-sentinel/`, and a value without a trailing slash is normalised to end in one before
`approvals/` is appended. The CLI dashboard also maps `GET /approvals/{id}` to redirect to
`/ai-sentinel/approvals/{id}`, so a bare-host `dashboardUrl` still lands on the page.

## Testing

- Command parsing: every validation rule above, including IPv6 and IPv4-mapped addresses.
- Middleware with `TestServer`: trusted range + header → authenticated; outside range + header → anonymous; trusted
  range, missing, empty, duplicate, overlong or control-character header → anonymous; local-approver on loopback →
  OS user; header ignored in local-approver mode.
- End to end against a temp audit file and a temp approvals.db: a request created through `SqliteApprovalStore`,
  approved through the dashboard with a proxy header, ends Active with `approver_id` = header value and exactly one
  `APPROVED` entry in the audit file, with an intact chain. Same for deny. Without approvals the audit file is opened
  read-only (existing tests keep passing).
- CSRF: cross-site `Sec-Fetch-Site` → 403; mismatched `Origin` → 403; same-origin → passes; no headers → passes; for
  both `MapAISentinel` and `UseAISentinel`.
- Detail page: pending request renders redacted arguments and encoded fields; unknown id → "no longer pending";
  non-admin store → external message; `no-store` header.
- Webhook text link for sqlite with and without a trailing slash on `dashboardUrl`; entra-pim unchanged.
- Run test DLLs directly, AI.Sentinel.Tests with `-noclass "*DetectorRegistrationTrimTests"`, and the format check.

## Docs

- `integrations/claude-code.md` (and the Copilot/MCP integration pages if they repeat it): replace "shows no approvals
  panel" with the new flags.
- `approvals/dashboard.md`: the detail page, the CSRF rule, the CLI dashboard as a host, a forward-auth example
  (oauth2-proxy and Authelia header names).
- `approvals/cli-config.md`: `dashboardUrl` includes the prefix; the `text` link is per request for sqlite.
- CLI reference for `sentinel dashboard`.

## Left to the builder

- Class and file names, how the handlers learn about an Entra PIM backend without a store, how the detail page is
  rendered (string builder like the panel, or a small template in `wwwroot`).
- Whether `--trusted-proxy`/`--local-approver` without approvals is a note or an error.
- How `ApprovalNotifierSettings` learns the backend for the link rule.
- Commit split, within one commit per plan task.
