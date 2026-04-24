# MCP Proxy v1 Design

**Goal:** Ship `sentinel-mcp proxy --target <cmd> [<args>...]` — a stdio MCP middleware that intercepts `tools/call` and `prompts/get`, scans through the AI.Sentinel detector pipeline, and blocks threats by turning them into JSON-RPC errors. Supersedes the April 2026-04-23 MCP portion of the combined hook+MCP plan, which predated our read of the `ModelContextProtocol` SDK.

**Architecture:** SDK-native. The proxy is a single process that terminates an `McpServer` on its own stdin/stdout (host-facing) and owns an `McpClient` connected via `StdioClientTransport` to the target subprocess. Sentinel runs inside two `McpRequestFilter<TRequest, TResult>` instances registered on the server. Everything else forwards through default SDK handlers.

**Tech Stack:** `ModelContextProtocol 1.2.*` (Core) for MCP transport and typed models, `Microsoft.Extensions.AI` for `ChatMessage` / detector pipeline plumbing via AI.Sentinel core, `System.Text.Json` source generators for AOT-safe argument serialisation.

**Package surface:** `AI.Sentinel.Mcp` (library, `net8.0;net9.0`) already scaffolded. `AI.Sentinel.Mcp.Cli` (new `net8.0` dotnet tool, optionally AOT-publishable via the same `PackAsTool` conditional we just shipped for the hook CLIs).

---

## Why this supersedes the April plan

The April plan (`docs/plans/2026-04-23-claude-code-mcp-adapters.md`, Tasks 7-10) sketched a hand-rolled JSON-RPC bridge with separate `RequestInterceptor` / `ResponseInterceptor` classes. The SDK probe in this session revealed three types that make that architecture obsolete:

- `McpServer` + `McpClient` — a full typed session on each side. We never read or write raw JSON-RPC.
- `McpRequestFilter<TRequest, TResult>` — first-class middleware around a typed request/response pair. The filter *is* the interceptor and the forwarder, collapsed.
- `McpException` + `McpErrorCode` — typed error throwing, serialised to the wire by the SDK.

Net effect: the interceptor and forwarder become one `McpRequestFilter` implementation. No custom framing, no manual `-32000` error JSON, no stdio bridge. Tasks 7 ("forward-only") and 8-9 ("interception layers") are no longer distinct.

---

## Section 1 — Architecture

```
MCP host  ⇆  [McpServer on proxy stdin/stdout]  ⇆  [filters]  ⇆  [McpClient via StdioClientTransport]  ⇆  target subprocess
```

- **`McpServer`** terminates the host side. Reads MCP frames from process stdin, writes to stdout. Hosts a handler registry that the proxy populates with two `McpRequestFilter` instances and delegates the rest to a pass-through to the upstream client.
- **`McpClient`** owns the target side. Spawns the target command (`uvx mcp-server-filesystem /home/me` etc.) via `StdioClientTransport`, performs the MCP `initialize` handshake against it, and exposes typed methods (`CallToolAsync`, `GetPromptAsync`, `ListToolsAsync`, …).
- **`McpProxy`** is the library entry point. Constructs both sides, registers the filters, and returns a Task that completes when the session ends.

Two filters registered, nothing else:

- `McpRequestFilter<CallToolRequestParams, CallToolResult>`
- `McpRequestFilter<GetPromptRequestParams, GetPromptResult>`

Both execute the same shape:

1. Build `ChatMessage[]` for the request (prompt-direction scan).
2. Call `SentinelPipeline.ScanMessagesAsync(messages)`. If it returns a `SentinelError.ThreatDetected`, throw `McpException(McpErrorCode.InternalError, "Blocked by AI.Sentinel: {detector} {severity}: {reason}")`. The SDK serialises to JSON-RPC error on the wire.
3. Forward to the upstream client (`CallToolAsync` / `GetPromptAsync`).
4. Build `ChatMessage[]` for the result (response-direction scan). Run `ScanMessagesAsync` again. Same throw-on-threat logic.
5. Return the result.

`ScanMessagesAsync` (not the two-pass `GetResponseResultAsync`) — one scan per direction, no phantom response pass. Same optimisation we shipped for the hook adapters.

No separate forward-only stage. The filter is the forwarder from day one.

---

## Section 2 — Detector pipeline construction

`AI.Sentinel.Mcp` does **not** use `services.AddAISentinel(...)`. That registers every detector, which is the wrong default — MCP tool arguments and tool results are structured data, not LLM output. Operational detectors (`BlankResponseDetector`, `RepetitionLoopDetector`) and hallucination detectors (`ConfidenceDecayDetector`, etc.) were designed for LLM-generated text and produce noise on JSON args / short tool responses.

Instead the library constructs a `SentinelPipeline` directly via an internal helper:

```csharp
internal static class McpPipelineFactory
{
    public static SentinelPipeline Create(HookConfig config, bool allDetectors)
    {
        var detectors = allDetectors
            ? BuildAllDetectors()
            : BuildSecurityDetectors();

        var options = new SentinelOptions
        {
            OnCritical = config.OnCritical,
            OnHigh     = config.OnHigh,
            OnMedium   = config.OnMedium,
            OnLow      = config.OnLow,
        };

        return new SentinelPipeline(
            innerClient:        UnusedChatClient.Instance,
            pipeline:           new DetectionPipeline(detectors, escalationClient: null),
            auditStore:         new RingBufferAuditStore(capacity: 1024),
            interventionEngine: new InterventionEngine(options, mediator: null),
            options:            options);
    }
}
```

`BuildSecurityDetectors()` returns the nine security detectors already grouped in the benchmark harness's `PipelineFactory.SecurityOnly()`:

- `PromptInjectionDetector`
- `JailbreakDetector`
- `CredentialExposureDetector`
- `DataExfiltrationDetector`
- `PrivilegeEscalationDetector`
- `ToolPoisoningDetector`
- `IndirectInjectionDetector`
- `AgentImpersonationDetector`
- `CovertChannelDetector`

All regex/pattern-based. They scan dangerous patterns that remain recognisable inside serialised JSON argument maps.

`BuildAllDetectors()` enumerates every detector that `AddAISentinel` registers. Duplication risk: if `AddAISentinel` grows, the two lists drift. Mitigations — one unit test (`McpPipelineFactory_AllPreset_MatchesAddAISentinel`) asserts `BuildAllDetectors().Length >= ServiceCollectionExtensions.AddAISentinel.DetectorCount` via reflection-free counts. The alternative (exposing detector metadata on the core library or using DI reflection) is worse: more API surface or less AOT-friendly.

`UnusedChatClient` is the same placeholder from `AI.Sentinel.ClaudeCode` — throws if invoked. `ScanMessagesAsync` never reaches the inner client, so the throw stays theoretical.

### Configuration

Env vars only — decided in the design pass. MCP hosts (Claude Desktop, Cursor, Continue, Copilot) all accept per-server `env` maps in their config JSON.

| Variable | Default | Semantics |
|---|---|---|
| `SENTINEL_HOOK_ON_CRITICAL` | `Block` | Shared with hooks. |
| `SENTINEL_HOOK_ON_HIGH` | `Block` | Shared. |
| `SENTINEL_HOOK_ON_MEDIUM` | `Warn` | Shared. |
| `SENTINEL_HOOK_ON_LOW` | `Allow` | Shared. |
| `SENTINEL_MCP_DETECTORS` | `security` | `security` or `all`. Anything else → log warning, default to `security`. |
| `SENTINEL_MCP_MAX_SCAN_BYTES` | `262144` (256 KB) | Truncation cap for text extracted from tool results. |

No CLI flags for severity/detector config in v1. CLI flags become sugar if users ask; keeping the shipping interface to one surface (env vars) saves documentation and test matrix.

---

## Section 3 — Request/response → `ChatMessage[]` mapping

### `tools/call`

**Request scan (args direction):**

```csharp
[ChatMessage(User, $"tool:{req.Name} input:{JsonSerializer.Serialize(req.Arguments, McpJsonContext.Default.IDictionaryStringJsonElement)}")]
```

`req.Name` is `CallToolRequestParams.Name`. `req.Arguments` is `IDictionary<string, JsonElement>?`. Serialised through a source-generated `McpJsonContext` so no reflection-based serialisation on the hot path — keeps the AOT publish clean.

**Response scan (result direction):**

```csharp
[
  ChatMessage(User,      $"tool:{req.Name} input:..."),           // same prompt, gives detectors conversational context
  ChatMessage(Assistant, ExtractScannableText(result.Content))    // concatenated text blocks, Assistant-role
]
```

Only `TextContentBlock`s are scanned. `ImageContentBlock`, `AudioContentBlock`, and `EmbeddedResourceContentBlock` are skipped — no usable text, out of scope for v1.

Text blocks joined with `\n---\n` so:
- Detectors see all blocks in one scan.
- Block boundaries are visible — some detectors (e.g. `IndirectInjectionDetector`) care about role transitions within content.

If `ExtractScannableText` yields an empty string (every block was non-text), the response scan is skipped entirely. No scan, no false positives from detectors firing on empty input.

Assistant-role placement is deliberate — detectors like `IndirectInjectionDetector` look for injection inside *assistant*-role content (tool output attempting to steer the model). Matches the `post-tool-use` hook mapping.

### `prompts/get`

**Request scan:** skipped. Prompts are metadata (name + optional arguments). No user content in the request that hasn't already been handled elsewhere.

**Response scan:**

```csharp
[ChatMessage(Assistant, ConcatenatePromptMessages(result.Messages))]
```

`GetPromptResult.Messages` is a list of `PromptMessage` (each with role + content blocks). All flattened into one Assistant-role string — the threat model is "target MCP server delivers adversarial prompt content", and the role-of-origin inside the result doesn't matter once you've decided to trust nothing from the target.

### Streaming

`CallToolResult` is non-streaming in 1.2.0 — the SDK buffers the result before the filter sees it. Single scan on the complete result.

### Size guard

`ExtractScannableText` enforces `SENTINEL_MCP_MAX_SCAN_BYTES` (default 256 KB). Exceeded → truncate at the limit, append `… [truncated N bytes]`, scan the prefix. Documented as a known limitation: a payload past byte 256 K won't be caught by detection. The alternative — unbounded scan time on a hostile target returning 100 MB — is worse. Raising the cap is a one-line env var.

Truncation affects the *scan input only*. The proxy still forwards the full result to the host unchanged.

---

## Section 4 — `sentinel-mcp` CLI

Single binary, single subcommand. Hand-rolled arg parsing — no `System.CommandLine` dependency.

**Shape:**

```
sentinel-mcp proxy --target <command> [<target-args>...]
```

**Examples:**

```
sentinel-mcp proxy --target uvx mcp-server-filesystem /home/me
sentinel-mcp proxy --target npx @modelcontextprotocol/server-github
```

**Parsing rules:**

- First positional must be `proxy`. Unknown subcommands → exit 1 with usage on stderr. (Future-proofs for `sentinel-mcp validate` / `version` etc., though v1 ships only `proxy`.)
- `--target <cmd>` is mandatory. Value is the target executable.
- Everything after `--target <cmd>` up to end-of-args is the target's own argument list. No `--` separator needed.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Clean shutdown — MCP `shutdown` received or host closed stdin. |
| `1` | Usage error — missing `--target`, unknown subcommand, malformed args. |
| `2` | Target subprocess failed to start or died unexpectedly. |

**Logging:** all diagnostics → stderr. Stdout is sacred — it's the MCP wire. Per-call one-liner, always-on:

```
[sentinel-mcp] event=tools/call decision=Allow tool=read_file session=<mcp-session-id>
[sentinel-mcp] event=tools/call decision=Block tool=write_file detector=SEC-01 severity=Critical session=<mcp-session-id>
```

No `SENTINEL_MCP_VERBOSE` gate — the proxy is long-lived and operators need per-call visibility. Verbose-gating made sense for hooks (fresh process per call, noisy otherwise); here the signal-to-noise is correct by default.

**`Program.RunAsync(string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr)`** is the testable entry point, matching the hook CLI pattern.

**csproj** mirrors the hook CLI pattern we just shipped:

```xml
<TargetFrameworks></TargetFrameworks>
<TargetFramework>net8.0</TargetFramework>
<OutputType>Exe</OutputType>
<PackAsTool Condition="'$(PublishAot)' != 'true'">true</PackAsTool>
<ToolCommandName>sentinel-mcp</ToolCommandName>
<InvariantGlobalization Condition="'$(PublishAot)' == 'true'">true</InvariantGlobalization>
```

`dotnet pack` → dotnet tool package. `dotnet publish -p:PublishAot=true` → ~6 MB native binary. The `.github/workflows/aot-publish.yml` matrix gets the new csproj appended so AOT regression is caught in CI.

---

## Section 5 — Failure modes

### Target MCP server crashes / disconnects mid-session

Proxy exits with code 2. Current MCP hosts (Claude Desktop, Cursor) are resilient to server death — they mark the server unavailable and surface a clear error to the user. Reimplementing restart/back-off inside the proxy is a systemd-shaped rabbit hole and provides no benefit over the host doing it.

### Sentinel pipeline itself throws (bug, detector misbehaviour)

Fail-open. Log a one-liner to stderr (`[sentinel-mcp] event=tools/call decision=FailOpen reason=<exception-message>`), forward the tool call verbatim. A broken scanner is an operator problem — it must not appear to the user as a security decision. Matches the hook CLI's `RunCoreAsync` try/catch contract (exit 1 = operator error, not a block).

### Target stalls — no response to `tools/call` for > N seconds

No proxy-level timeout in v1. Hosts have their own timeouts (Claude Desktop, Cursor both do). Compounding two timeouts creates confusing failure modes. Easy to add later via `SENTINEL_MCP_TIMEOUT_SEC` when the need is concrete.

---

## Section 6 — Testing

### `FakeMcpServer` — in-memory target

A thin `McpServer` instance wrapped around a paired `Stream` pair (not spawning a subprocess). Registers canned handlers:

- `tools/list` returns two fake tools: `read_file`, `write_file`.
- `tools/call` echoes the args as text content by default. `FakeMcpServer.EnqueueResult(...)` pre-seeds a response for "malicious output" tests.
- `prompts/list` + `prompts/get` similar pattern, with `EnqueuePrompt(...)` for adversarial payloads.
- Explicit `SimulateCrash()` closes the stream mid-session for the crash test.

Proxy-under-test connects via an in-memory `StreamClientTransport`, not `StdioClientTransport` — avoids subprocess I/O in tests. The proxy's server side uses a `StreamServerTransport` that the test driver reads from to simulate the host.

### Library tests (`tests/AI.Sentinel.Tests/Mcp/`)

| Test | Verifies |
|---|---|
| `Proxy_Initialize_ForwardsToTarget` | `initialize` reaches fake; capabilities returned match. |
| `Proxy_ToolsList_ForwardsToTarget` | `tools/list` passes through (control-plane stays unscanned). |
| `Proxy_ToolCall_CleanArgs_ForwardsAndReturnsResult` | Non-threatening call reaches target, result reaches host unchanged. |
| `Proxy_ToolCall_InjectionArgs_BlocksBeforeTarget` | `ignore all previous instructions` in args → `McpException` with SEC-01; fake target never receives the call. |
| `Proxy_ToolCall_MaliciousResult_BlocksAfterTarget` | Target returns injection text — proxy turns into JSON-RPC error. |
| `Proxy_ToolCall_NonTextResult_SkipsResponseScan` | Target returns only an image block — proxy forwards unscanned. |
| `Proxy_ToolCall_OversizeResult_TruncatesAtLimit` | Target returns 1 MB text with `SENTINEL_MCP_MAX_SCAN_BYTES=4096` — scan operates on prefix, full content forwarded. |
| `Proxy_PromptsGet_MaliciousPrompt_BlocksWithError` | Target returns adversarial prompt → blocked. |
| `Proxy_TargetCrash_ProxyExits` | Fake closes stream mid-session → proxy exits with code 2. |
| `Proxy_SentinelThrows_FailsOpen` | Injected throwing detector → tool call forwarded, stderr warning emitted. |
| `McpPipelineFactory_SecurityPreset_Uses9Detectors` | Count assertion on security preset. |
| `McpPipelineFactory_AllPreset_IsSupersetOfSecurity` | Guards against preset divergence. |

### CLI tests

| Test | Verifies |
|---|---|
| `Cli_NoArgs_ExitsOneWithUsage` | Bare `sentinel-mcp` → exit 1, usage on stderr. |
| `Cli_ProxyNoTarget_ExitsOneWithUsage` | `sentinel-mcp proxy` → exit 1, mentions `--target`. |
| `Cli_UnknownSubcommand_ExitsOne` | `sentinel-mcp foo` → exit 1. |

End-to-end CLI tests (real subprocess spawn) are out of scope — the `FakeMcpServer` library tests cover the same surface with less flakiness and no install dependency. The AOT-publish workflow already validates the binary starts; that is the smoke coverage.

### Isolation

All MCP tests that mutate `Environment` for env-var config join the existing `[Collection("NonParallel")]` collection.

---

## Files changed

### New

```
src/AI.Sentinel.Mcp/
  McpProxy.cs
  McpPipelineFactory.cs
  ToolCallInterceptor.cs
  PromptGetInterceptor.cs
  MessageBuilder.cs
  McpJsonContext.cs

src/AI.Sentinel.Mcp.Cli/
  AI.Sentinel.Mcp.Cli.csproj
  Program.cs
  ProxyCommand.cs

tests/AI.Sentinel.Tests/Mcp/
  FakeMcpServer.cs
  McpProxyTests.cs
  McpCliTests.cs
  McpPipelineFactoryTests.cs
```

### Modified

- `AI.Sentinel.slnx` — add `AI.Sentinel.Mcp.Cli` project.
- `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj` — project references to `AI.Sentinel.Mcp` and `AI.Sentinel.Mcp.Cli`.
- `README.md` — new MCP proxy section under Agent integrations, package table row, install + host-config example.
- `docs/BACKLOG.md` — remove MCP proxy entry; add deferred-item entries (see below).
- `.github/workflows/aot-publish.yml` — append `AI.Sentinel.Mcp.Cli.csproj` to matrix.

---

## Deferred (tracked in BACKLOG)

1. **`resources/read` interception** — requires MIME-type gate + size cap + false-positive tuning on file-content scans. Real attack vector but deserves its own focused session.
2. **SSE / HTTP transport** — SDK supports it; stdio-only v1 keeps CLI shape simple.
3. **CLI flags for severity/detector config** — env vars are the shipping interface; flags are sugar.
4. **Per-target detector tuning** — one detector set per proxy instance. Multiple policies = multiple `sentinel-mcp` instances.
5. **Structured audit export** — `RingBufferAuditStore` stays internal. Exposing a JSON/file sink belongs with the wider persistent-audit-store backlog item.
6. **Proxy-level request timeout** (`SENTINEL_MCP_TIMEOUT_SEC`) — add when concrete need appears.

---

## Commit shape (for plan writer)

1. `feat(mcp): add McpPipelineFactory + MessageBuilder foundation`
2. `feat(mcp): add FakeMcpServer test harness`
3. `feat(mcp): forward-only McpProxy wired via McpServer + McpClient`
4. `feat(mcp): intercept tools/call with McpRequestFilter`
5. `feat(mcp): intercept prompts/get with McpRequestFilter`
6. `feat(mcp): sentinel-mcp Cli + proxy subcommand (AOT-ready)`
7. `docs+ci: document sentinel-mcp + extend AOT workflow matrix`
