---
sidebar_position: 3
title: Dashboard
---

# Dashboard

`AI.Sentinel.AspNetCore` ships an embedded real-time dashboard. No JS framework, no build step — HTMX + Server-Sent Events served from embedded resources.

![AI.Sentinel dashboard — TRS gauge at ISOLATE, severity counters, live event feed with hash-chained detections](/img/screenshots/dashboard-desktop.png)

## Mount

```csharp
// Program.cs
app.MapAISentinel("/ai-sentinel");
```

Open `http://localhost:5000/ai-sentinel` and you'll see the live UI. The path prefix is whatever you choose — `"/admin/sentinel"`, `"/internal/security"`, anything.

`MapAISentinel` registers the dashboard endpoints on the host's `IEndpointRouteBuilder`, so they participate in normal endpoint matching and outrank catch-all fallbacks (e.g. `MapFallbackToFile("index.html")` in Blazor WASM hosts) by route specificity. The legacy `app.UseAISentinel(...)` is still supported for back-compat, but it wraps the dashboard in a sub-pipeline that loses to root-level fallbacks — prefer `MapAISentinel`.

## What the dashboard shows

- **Threat Risk Score** — live ring gauge (0–100) with four bands:
  - **SAFE** (0–14)
  - **WATCH** (15–39)
  - **ALERT** (40–69)
  - **ISOLATE** (70–100)
- **Live event feed** — the newest 50 detections streamed via Server-Sent Events with severity badge, detector ID, reason, session ID, source, and timestamp
- **Source** — a column and a `source` filter naming the tool that wrote each entry (`claude-code`, `copilot`, `mcp`; blank for in-process apps). Click a source to filter on it, as with session. The export honours the filter
- **Detector hit stats** — which detectors fire most over the current window

The feed updates as new audit entries land — no polling, no manual refresh.

## Browse the local audit file

The Claude Code hook, the Copilot hook and the MCP proxy record to a local SQLite file by default. The `sentinel dashboard` command in the `AI.Sentinel.Cli` tool serves this same dashboard over that file, without an ASP.NET app:

```bash
dotnet tool install -g AI.Sentinel.Cli
sentinel dashboard [--db <path>] [--port <port>]   # more options below
```

It serves `http://127.0.0.1:5170/ai-sentinel/` by default, listens on loopback unless `--bind` says otherwise, and does not open a browser. Without `--db` it reads the file the CLIs write, `ai-sentinel/audit.db` under your per-user data folder. On start it prints `Audit chain intact: N entries` or `Audit chain broken at entry {id}`. It refuses a file that does not exist. Without an approval config it opens the file read-only and shows no approvals to act on: it never creates the file, never upgrades an older schema (run a hook or the MCP proxy once to upgrade it), and never appends. SQLite may create `-wal` and `-shm` files next to it. It needs the ASP.NET Core runtime, which the .NET SDK includes.

### Options

| Option | Default | Notes |
|---|---|---|
| `--db <path>` | the file the CLIs write | The audit SQLite file. |
| `--port <port>` | `5170` | `0` picks a free port. |
| `--bind <ip>` | `127.0.0.1` | The address to listen on. A non-loopback address needs `--trusted-proxy`. A scoped IPv6 address (with a `%` zone) is refused. |
| `--approval-config <path>` | `SENTINEL_APPROVAL_CONFIG` | The [approval config](../approvals/cli-config). With a `sqlite` backend the dashboard lists pending requests and records approve and deny. |
| `--trusted-proxy <cidr or ip>` | none | A reverse proxy whose user header is trusted. Repeatable. |
| `--user-header <name>` | `X-Auth-Request-User` | The header the proxy sets to the user name. Only valid together with `--trusted-proxy`. |
| `--public-host <name>` | none | A host name or IP address, without port, scheme or path, that the trusted proxy forwards in the `Host` header. Repeatable. Only valid together with `--trusted-proxy`. `localhost`, `127.0.0.1` and `[::1]` are always accepted, and so is the `--bind` address when it is not a wildcard. |
| `--local-approver` | off | Approve and deny as the current OS user. Needs a loopback `--bind` and cannot be combined with `--trusted-proxy`. |

Approving from the CLI dashboard, who counts as an approver and the forward-auth setup are described in [the CLI dashboard as an approval host](../approvals/dashboard#the-cli-dashboard-as-an-approval-host). See [Claude Code → Audit destination](../integrations/claude-code#audit-destination) for what is recorded.

## Protect it

The dashboard exposes audit data, so don't expose it to the public internet without authentication. `MapAISentinel` returns a `RouteGroupBuilder` so you can chain endpoint conventions:

```csharp
app.MapAISentinel("/ai-sentinel")
   .RequireAuthorization("DashboardAdmins");

// Or with rate limiting:
app.MapAISentinel("/ai-sentinel")
   .RequireAuthorization()
   .RequireRateLimiting("dashboard");
```

For host-level filters that aren't endpoint conventions (IP allowlists, custom auth handlers), call `app.UseWhen` on the prefix path before the endpoint matching:

```csharp
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/ai-sentinel"),
    branch => branch.Use(RequireInternalNetwork));   // your IP allowlist middleware

app.MapAISentinel("/ai-sentinel");
```

The legacy `UseAISentinel("/ai-sentinel", branch => ...)` overload is also still supported if you prefer the sub-pipeline pattern, but be aware of the fallback-routing hazard described above.

## Multi-instance deployments

The default `RingBufferAuditStore` is in-process. In a horizontally-scaled deployment each instance has its own ring buffer, so each instance's dashboard shows only its own events.

For a unified view across instances, route audit entries to a shared persistent store ([SQLite](../audit-forwarders/sqlite) on a shared volume, or a [forwarder](../audit-forwarders/overview) to Azure Sentinel / OpenTelemetry / Splunk) and visualize there.

## What the dashboard does NOT do

- **Acknowledge / silence alerts** — read-only today; alert acknowledgment is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md)
- **Per-session timeline view** — global feed only, per-session view is on the backlog
- **Export audit log** — use the [`AI.Sentinel.Cli`](https://www.nuget.org/packages/AI.Sentinel.Cli) `replay` tool for offline NDJSON export
- **Configuration UI** — read-only. All configuration is at app startup via `services.AddAISentinel(opts => ...)`

## Verify the dashboard works

A quick smoke test:

```csharp
// Register, mount
builder.Services.AddAISentinel(opts => opts.OnHigh = SentinelAction.Alert);
builder.Services.AddChatClient(p => p.UseAISentinel().Use(new OpenAIChatClient(...)));
app.MapAISentinel("/ai-sentinel");

// Send a known-bad prompt
await chatClient.GetResponseAsync(new[]
{
    new ChatMessage(ChatRole.User, "ignore all previous instructions")
});
```

Open the dashboard. You should see a `SEC-01 PromptInjection` event in the live feed within ~1 second of the chat call returning.

## Next: [Architecture](../core-concepts/architecture) — how the two-pass pipeline flows
