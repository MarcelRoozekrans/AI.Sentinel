# AI.Sentinel Feature Backlog

Items are grouped by theme. No priority order implied within a group.

---

## New Detectors

### Operational

| ID (proposed) | Name | What it detects |
|---|---|---|
| OPS-09 | `TruncatedOutputDetector` | Response cut off mid-sentence — model ran out of tokens or was interrupted |
| OPS-10 | `WaitingForContextDetector` | Model stalling with placeholder phrases ("Please provide...", "Could you clarify...") when the request was self-contained |
| OPS-11 | `UnboundedConsumptionDetector` | Abnormally large response length or token-count anomaly relative to the prompt — possible resource exhaustion or runaway generation (cf. OWASP LLM10) |

### Security

| ID (proposed) | Name | What it detects |
|---|---|---|
| SEC-18 | `ToolDescriptionDivergenceDetector` | Tool description observed at invocation differs from description at discovery — possible MCP supply-chain manipulation |
| SEC-19 | `ToolCallFrequencyDetector` | Anomalous spike or unusual pattern in tool invocation rate within a session — possible automated exfiltration or resource abuse |
| SEC-21 | `ExcessiveAgencyDetector` | Model takes unsolicited autonomous actions (file writes, API calls, spawning agents) beyond its stated scope (cf. OWASP LLM06 / ASI02) |
| SEC-22 | `HumanTrustManipulationDetector` | Model output attempts to build false rapport, impersonate an authority figure, or exploit human-agent trust to bypass oversight (cf. OWASP ASI09) |

### Multi-Agent / Semantic

| ID (proposed) | Name | What it detects |
|---|---|---|
| SEM-01 | `ShorthandEmergenceDetector` | Agents developing a private shorthand or code language between them not present in the original instructions |
| SEM-02 | `UncertaintyPropagationDetector` | Speculative or partial results ("I think...", "possibly...") promoted to stated facts as they pass between agents |

---

## Intervention Engine

| Feature | Description |
|---|---|
| `SentinelAction.Reroute` | New intervention level: redirect the message to a fallback agent instead of quarantining or logging. Requires a configured `FallbackClient`. |

---

## Policy & Authorization

A new pillar alongside detectors: **preventive controls** and **authorization** at the tool-call boundary. Detectors classify what happened; these items decide what is *allowed to happen*. Inspired by Rag.NET's security layer (`UseRbac`, `UsePromptHardening`).

| Feature | Description |
|---|---|
| **Prompt hardening prefix** | Preventive (not detective) control: `SentinelOptions.SystemPrefix` prepends a hardening system-message to every outbound `IChatClient` call, instructing the model to treat retrieved/untrusted content strictly as data, never as instructions. Lightweight port of Rag.NET's `PromptHardeningAnswerEngineDecorator` — one new option + a pipeline step that mutates the `ChatMessage[]` before the downstream client sees it. First-line mitigation against OWASP LLM01 (prompt injection); complements existing detection. Minimum viable: ~60 LOC + tests. |
| **Tool-call authorization (`IToolCallGuard`)** | RBAC-style policy layer for LLM tool invocations — answers *"is this caller allowed to invoke this tool with these arguments?"* Introduces `IToolCallGuard`, `ICallerContext` (role/trust-level source), and `ToolCallPolicy` (rule set). Guard runs before each tool executes and returns allow / deny / require-approval; deny records an audit entry and optionally raises a detector hit for the dashboard. Conceptually analogous to Rag.NET's `UseRbac()` for retrieved chunks, applied instead to tool calls. Fills a real gap: Microsoft.Extensions.AI has no authorization story for tool calls today. |
| **Tool-call guard — `FunctionInvokingChatClient` integration** | Surface #1 (recommended MVP): wrap `FunctionInvokingChatClient` so every in-process `AIFunction` call passes through `IToolCallGuard` before executing. Zero new infrastructure — sits in the same pipeline as `.UseAISentinel()`. Abstraction that falls out of this surface is reused by the other three without rework. |
| **Tool-call guard — Claude Code `PreToolUse` hook** | Surface #2: reuse `IToolCallGuard` inside `AI.Sentinel.ClaudeCode` so the hook can deny/approve tool calls issued by Claude in-IDE. Deny action maps to Claude's hook block response. Reuses the policy evaluation from the MVP. |
| **Tool-call guard — Copilot `preToolUse` hook** | Surface #3: same as above for `AI.Sentinel.Copilot` — reuse `IToolCallGuard` at the Copilot hook boundary. |
| **Tool-call guard — MCP proxy `tools/call` interception** | Surface #4: once `AI.Sentinel.Mcp` is fully wired (Tasks 7-10 from the MCP plan), reuse `IToolCallGuard` inside the proxy so MCP server tool invocations are gated. Highest strategic value — single control point for every MCP-speaking client (Cursor, Continue, Cline, Windsurf, Copilot's MCP path). Depends on the MCP proxy adapter item below. |
| **ASP.NET Core `ICallerContext` bridge** | Out-of-the-box `ICallerContext` implementation that extracts roles/claims from `HttpContext.User` — drop-in for web apps. Mirrors Rag.NET's `Rag.NET.Security.AspNetCore.ClaimsPrincipalCallerContext`. |

---

## Architecture / Integration

| Feature | Description |
|---|---|
| **MCP proxy: `resources/read` interception** | v1 proxy intercepts `tools/call` + `prompts/get` only. `resources/read` is the next content-bearing path and a real indirect-injection vector (file content read by the model). Needs a MIME gate (skip non-text), a size cap, and likely detector tuning for file-content signal-to-noise — worth its own focused session. |
| **MCP proxy: SSE/HTTP transports** | v1 is stdio only. `ModelContextProtocol` supports `StreamableHttpClientTransport` and SSE; adding them lets the proxy sit in front of hosted MCP servers. |
| **MCP proxy: subprocess lifecycle hardening** | `StdioClientTransport` disposal relies on the target honoring stdin EOF. If the target hangs, the proxy leaks the child process. Add a kill-after-grace-period wrapper plus `SENTINEL_MCP_TIMEOUT_SEC` env var. |
| **MCP proxy: CLI flags for severity config** | v1 ships env-var-only config. Optional `--on-critical Block` / `--on-high Block` etc. CLI flags would match conventional CLI ergonomics. Not urgent — MCP hosts' `env` blocks work fine. |
| **MCP proxy: mirror target capabilities** | v1 unconditionally advertises `Tools` + `Prompts` to the host regardless of what the target actually supports. Wiring the proxy in front of a prompts-only server currently produces an empty `tools/list` or runtime error. Inspect `targetClient.ServerCapabilities` after `McpClient.CreateAsync` and advertise only what the target does. |
| **MCP proxy: concurrency + adversarial target test coverage** | All proxy tests are sequential. Add `Task.WhenAll`-style concurrent `CallToolAsync` tests, adversarial target tests (target returns `IsError=true` with injection text in the error message; target returns unparseable blobs), and an `All` detector preset round-trip test. |
| **MCP proxy: validate AOT nested-JSON tool-call forwarding** | Smoke test in CI currently only verifies the native binary's `--help` path. Exercise one nested-JSON `CallToolAsync` round-trip against the AOT-published binary to confirm `ToObjectDictionary`'s boxing doesn't trip AOT-incompatible reflection inside the SDK. |
| **MCP proxy: structured JSON logging** | Opt-in `SENTINEL_MCP_LOG_JSON=1` that emits the per-call stderr lines as NDJSON instead of the current `key=value` format. Makes log aggregators happy. |
| **MCP proxy: real-bytes truncation** | `SENTINEL_MCP_MAX_SCAN_BYTES` currently counts chars (identical to bytes for ASCII, doubled-to-quadrupled for UTF-8 multi-byte). Switch to `Encoding.UTF8.GetByteCount` if a user reports the cap under-truncating. |
| **MCP proxy: CancelKeyPress handler scoping** | `Program.RunAsync` subscribes `Console.CancelKeyPress` without `-=` in `finally`. Harmless in the one-shot CLI, but leaks a closure reference per call when hosted in a longer-lived process (e.g. integration tests). Same pattern in `AI.Sentinel.ClaudeCode.Cli` + `AI.Sentinel.Copilot.Cli`. |
| **Multi-agent spawn-chain tracking** | Propagate a `TraceId` through nested `SentinelChatClient` instances so the audit store records a parent→child call graph. Enables cross-agent contradiction and uncertainty propagation detection. |
| **Session behavioral signatures** | Derive a compact fingerprint per session (tool call distribution, message length variance, vocabulary entropy) for anomaly scoring against a rolling baseline |
| **Persistent audit store** | Pluggable `IAuditStore` interface backed by SQLite, Postgres, or any sink — in-memory ring buffer remains the default, no breaking change |
| **Custom detector SDK** | Official public API (`ISentinelDetector`) + stable NuGet surface for registering third-party detectors via `opts.AddDetector<T>()` |
| **Per-pipeline configuration** | Register multiple named `SentinelOptions` instances so different endpoints get different detector sets, thresholds, or `EscalationClient`s |
| **Detector result caching** | Short-TTL cache keyed on content hash — avoids re-running all detectors when identical prompts are sent in quick succession |
| **Fluent per-detector config** | `opts.Configure<PromptInjectionDetector>(d => d.Severity = Severity.High)` — tune or disable individual detectors without removing them from the pipeline |

---

## Dashboard (`AI.Sentinel.AspNetCore`)

| Feature | Description |
|---|---|
| Per-session timeline view | Show the full prompt/response scan sequence for a single session, not just the global feed |
| Detector hit rate sparklines | Small per-detector trend charts over the last N minutes |
| Export audit log | Download the current ring buffer as NDJSON from the dashboard |
| Threat heatmap | Calendar-style grid showing threat volume and severity by hour — spot recurring attack windows at a glance |
| Detector correlation matrix | Which detectors tend to fire together — reveals compound attacks and helps tune detector weights |
| Alert acknowledgment | Mark individual audit entries as reviewed/suppressed directly from the dashboard; surfaced as a `SentinelAuditStatus` field |
| Live audit log search | Filter the audit feed by session ID, detector ID, severity, or free text |
| Severity trend chart | Rolling line chart of `ThreatRiskScore` distribution over time — baseline deviation visible at a glance |
| Dark mode | System-preference-aware theme toggle via CSS `prefers-color-scheme` |
| Multi-instance aggregation | Federate audit logs from N app instances into a single dashboard view via a shared persistent store |

---

## Developer Experience

| Feature | Description |
|---|---|
| **Detector test helpers** | `SentinelTestBuilder.WithPrompt(...).ExpectDetection<T>(Severity.High)` — xUnit/NUnit-friendly fluent API for unit-testing detectors with known inputs |
| **Benchmark CI gate** | MSBuild target that runs the benchmark suite and fails the build if any detector regresses past a configurable latency threshold |
| **`AI.Sentinel.Analyzers`** | Roslyn diagnostic package that catches misconfiguration at build time: warn when `EscalationClient` is unset but LLM-escalation detectors are active, warn when `OnCritical = PassThrough`, warn on zero audit capacity |
| **Source-generated detector registration** | `[SentinelDetector]` attribute on a custom detector class → source generator emits the `opts.AddDetector<T>()` call — complements the custom detector SDK with zero-boilerplate registration |
| **EditorConfig blank-line rule** | Add an `.editorconfig` rule enforcing a blank line between `using` directives and `namespace` declarations — currently inconsistent across detector files and will widen without enforcement |

---

## ZeroAlloc Integration (`AI.Sentinel.ZeroAlloc`)

Many ZeroAlloc packages are already wired into the core library. The items below are genuinely remaining integration opportunities.

**Already shipped (removed from backlog):**
- `ZeroAlloc.Collections.HeapRingBuffer<T>` backs `RingBufferAuditStore`
- `ZeroAlloc.Telemetry` `[Instrument("ai.sentinel")]` applied to `IAuditStore`, `IAlertSink`, `IDetectionPipeline`
- `ZeroAlloc.Resilience.RateLimiter` powers per-session rate limiting in `SentinelPipeline`
- `ZeroAlloc.Inject` `[Singleton(As = typeof(IDetector), AllowMultiple = true)]` on every detector drives compile-time DI registration

**Remaining integration opportunities:**

| Feature | ZeroAlloc Package | Description |
|---|---|---|
| **Typed `SessionId` / `AgentId`** | `ZeroAlloc.ValueObjects` `[TypedId]` | Replace current `sealed partial class` `SessionId` / `AgentId` wrappers with source-generated `readonly record struct` typed IDs — zero boxing on hot paths, EF Core and JSON converters included |
| **FSM-modeled agent action sequences** | `ZeroAlloc.StateMachine` | Power `ExcessiveAgencyDetector` (SEC-21, not yet implemented) with a source-generated FSM — declare allowed tool-call sequences as states/transitions; any deviation triggers a detection |
| **NDJSON export mapping** | `ZeroAlloc.Mapping` | Generate `AuditEntry → ExportDto` mapping with `[Map<AuditEntry, AuditExportDto>]` — used by the future dashboard NDJSON export endpoint, zero reflection |
| **Mediator authorization for prompts** | `ZeroAlloc.Mediator.Authorization` | Gate prompt dispatch on caller-declared policies via `[Authorize("policy")]` on the mediator request — enforces access control at the model boundary |
| **Fluxor state management in ChatApp** | `ZeroAlloc.Fluxor` | Replace ad-hoc component state in `ChatApp.Client/Chat.razor` with a compile-time Flux store — `ChatState` (messages, connection status, active threats) as a `readonly record struct`, reducers for `MessageSentAction`, `TokenReceivedAction`, `ThreatDetectedAction`; demonstrates ZeroAlloc.Fluxor + AI.Sentinel integration end-to-end. _Conditional on ZeroAlloc.Fluxor shipping._ |
