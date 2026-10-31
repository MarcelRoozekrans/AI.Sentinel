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

## The CLI dashboard as an approval host

`sentinel dashboard` from the `AI.Sentinel.Cli` tool serves the same panel over the local audit file, so an approver can decide requests that the CLIs (`sentinel-hook`, `sentinel-copilot-hook`, `sentinel-mcp`) hold, without an ASP.NET app. See [Browse the local audit file](/docs/getting-started/dashboard#browse-the-local-audit-file) for the other options.

```bash
sentinel dashboard --approval-config ./approvals.json --local-approver
```

What the command does depends on the [approval config](/docs/approvals/cli-config). Pass it with `--approval-config <path>`, or set `SENTINEL_APPROVAL_CONFIG`.

| Config | Result |
|---|---|
| `backend: "sqlite"` | The panel lists pending requests, each links to its own page, and Approve and Deny work. The audit file is opened writable, so each decision is appended to the hash chain. |
| `backend: "entra-pim"` | The panel shows the [external approvals message](#when-the-store-doesnt-implement-iapprovaladmin). Approvers decide in the Azure portal. The audit file stays read-only. |
| No config, `backend: "none"` or an in-memory backend | No approvals. The audit file stays read-only. Startup prints `Approvals: off`, with the reason when there is one. An in-memory backend passed explicitly with `--approval-config` is an error, because it keeps nothing between processes. |

Startup prints an `Approvals:` line next to the audit-chain line. It names the backend and the identity mode, for example `Approvals: sqlite /var/lib/ai-sentinel/approvals.db, approver from X-Auth-Request-User via 10.0.0.0/8`. It never prints a header value.

### Who may approve

Without an identity, approve and deny return `401`, as for any unauthenticated dashboard. There are two ways to give the dashboard one. Both look at the socket peer address only and never at `X-Forwarded-For`.

**Local approver.** `--local-approver` treats every loopback request as the current OS user, and records that user name as the approver. It needs a loopback `--bind` and cannot be combined with `--trusted-proxy`. Every process and every OS user that can reach loopback on that machine counts as that user, so use it only on a single-user machine.

**Trusted proxy.** Put the dashboard behind a reverse proxy that authenticates the user and passes the name in a header:

```bash
sentinel dashboard \
  --approval-config ./approvals.json \
  --bind 0.0.0.0 --port 5170 \
  --trusted-proxy 10.0.0.0/8 \
  --user-header X-Auth-Request-User
```

- `--trusted-proxy` takes a CIDR range or one address, and can be repeated. IPv4-mapped IPv6 entries are treated as IPv4.
- `--user-header` defaults to `X-Auth-Request-User`, which oauth2-proxy sets. Use `Remote-User` for Authelia.
- The header is read only when the peer address is inside a trusted range. From anywhere else it is ignored.
- The value must be a single header value of at most 256 characters, with no control or Unicode format characters. Otherwise the request counts as anonymous and approve and deny return `401`.

A `--bind` that is not loopback needs at least one `--trusted-proxy`. With such a bind the dashboard refuses every request whose peer is neither loopback nor inside a trusted range, with `403`, so the audit data is not served to clients that bypass the proxy. A wildcard bind such as `0.0.0.0` prints a loopback URL on startup.

Whoever the proxy lets in can approve. Restrict the dashboard route in the proxy to the people allowed to approve.

A proxy on the same host is the common setup, so loopback stays allowed: `--trusted-proxy 127.0.0.1/32` works. Then any local process can also connect to the dashboard and send the user header itself, so the header is only as trustworthy as the machine. Do not use that setup on a machine with other users or untrusted processes.

#### Host check and `--public-host`

Every request must carry a `Host` the dashboard answers to, or it gets `403`. This stops DNS rebinding: a web page can point its own host name at `127.0.0.1`, which makes the dashboard same-origin for the browser. With a same-host proxy the peer is then a trusted proxy, so the page would also pass the user header check.

- A peer outside every trusted range must send `localhost`, `127.0.0.1` or `[::1]`, with any port. Otherwise the answer is `This dashboard only accepts requests addressed to localhost.`
- A trusted proxy must send one of those, one of the names given with `--public-host`, or the `--bind` address itself, compared without case and ignoring the port. Otherwise the answer is `This dashboard only accepts requests for its configured host names.`
- `--public-host <name>` is repeatable and only valid together with `--trusted-proxy`. The value is a host name or IP address, without port, scheme or path, for example `dash.example.com` or `192.0.2.10`.
- Startup lists the names on the `Approvals:` line.

nginx `proxy_pass http://192.0.2.10:5170;` sends the upstream address as `Host` by default, which is the `--bind` address and needs no flag. If you set `proxy_set_header Host $host;`, nginx forwards the public name, so pass `--public-host` with that name.

#### Forward-auth example

With oauth2-proxy in front of nginx, the proxy authenticates the user and nginx passes the name on:

```nginx
location /ai-sentinel/ {
    auth_request /oauth2/auth;
    auth_request_set $user $upstream_http_x_auth_request_user;
    proxy_set_header X-Auth-Request-User $user;
    proxy_pass http://192.0.2.10:5170;
}
```

Run `sentinel dashboard --bind 192.0.2.10 --trusted-proxy 192.0.2.20`, where `192.0.2.20` is the nginx host. For Authelia, use `auth_request_set $user $upstream_http_remote_user;` and `proxy_set_header Remote-User $user;`, and pass `--user-header Remote-User`.

nginx replaces any `X-Auth-Request-User` the client sent, which is what keeps the name trustworthy. Make sure your proxy does the same.

### Cross-site requests

Cookie-based forward auth sends its session cookie on a cross-site `POST`, so authentication alone does not show that the approver meant the click. The approve and deny endpoints therefore refuse a browser request marked cross-site with `403`:

- When the browser sends `Sec-Fetch-Site`, only `same-origin` and `none` pass.
- Otherwise a request with an `Origin` header passes only when its scheme, host and port match the request. A `null` or malformed origin is refused.
- A request with neither header, such as `curl`, passes. It is not browser-driven.

Behind a proxy that terminates TLS and forwards plain `http` without forwarded-header handling, the request scheme is `http`. A browser that then sends an `https` `Origin` but no `Sec-Fetch-Site` is refused. Current browsers send `Sec-Fetch-Site` and are not affected.

### The request page

`/ai-sentinel/approvals/{id}` shows one pending request: tool, caller, policy, request time, justification and the arguments, with Approve and Deny buttons and an optional deny reason. The arguments pass through the same redaction as the [webhook](/docs/approvals/cli-config#arguments): credentials and PII are replaced by placeholders. The page is sent with `Cache-Control: no-store` and cannot be framed. A request that is already decided or expired shows a short note instead.

`/approvals/{id}` at the root redirects to that page, so a `dashboardUrl` without the path prefix still works. With `sqlite`, the [notification](/docs/approvals/cli-config#payload) links to this page.

Deny without a reason records `denied via dashboard`.

## Programmatic access

If you'd rather drive approvals from your own UI:

- `GET /ai-sentinel/api/approvals` returns the same data as the panel's HTMX poll.
- `POST /ai-sentinel/api/approvals/{id}/approve` / `/deny` are the same endpoints the panel posts to.

Both are part of the [route group](/docs/getting-started/dashboard) and respect any `.RequireAuthorization(...)` you apply to it.
