# AI.Sentinel Feature Backlog

Items are grouped by theme. No priority order implied within a group.

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
| **PIM-style approval workflow** | Adds `RequireApproval` decision tier to `IToolCallGuard` for high-stakes tools (e.g. `delete_database`, `send_payment`). Pluggable `IApprovalStore` (in-memory + persistent backends), time-bound grants with TTL, dashboard Approve/Deny UI with justification, Mediator pending-approval notification, per-surface wait strategies. Strictly additive — doesn't break the binary v1 contract. |
| **`ZeroAlloc.Authorization.Abstractions` extraction** | Once `ZeroAlloc.Mediator.Authorization` ships, extract `ISecurityContext` / `IAuthorizationPolicy` / `[Authorize]` / `[AuthorizationPolicy]` into a shared package so AI.Sentinel and ZeroAlloc.Mediator share primitives. One `IAuthorizationPolicy` class works for both worlds. |
| **Async `IAuthorizationPolicy`** | Add `Task<bool> IsAuthorizedAsync(ISecurityContext)` overload. Coordinate with ZeroAlloc.Mediator.Authorization design before changing the interface. |
| **Source-gen-driven policy name lookup** | Replace startup reflection scan in `DefaultToolCallGuard` registration with a generated `name → factory` table. Cold-start performance optimisation. |
| **Policy timeout** | `opts.PolicyTimeout` with deny-on-timeout for I/O-bound policies (tenant lookup, etc.). |
| **`opts.AuditAllows`** | Opt-in compliance mode that also audits Allow decisions. |
| **`[Authorize]` attribute discovery for AIFunction-bound methods** | Translate method-level `[Authorize("policy")]` to a `RequireToolPolicy(funcName, "policy")` binding at AIFunction registration time. (Deferred from Task 8 to keep the in-process surface scope tight.) |

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
| **Dashboard category chips** | Add `Security` / `Hallucination` / `Operational` filter chips alongside the new `Authorization` chip — Task 12 shipped only `All` + `Authorization` because the others were never implemented. Decide category-mapping logic (likely a `DetectorCategory` switch on `DetectorId` prefix) and wire chips. |

---

## Developer Experience

| Feature | Description |
|---|---|
| **Detector test helpers** | `SentinelTestBuilder.WithPrompt(...).ExpectDetection<T>(Severity.High)` — xUnit/NUnit-friendly fluent API for unit-testing detectors with known inputs |
| **Multi-language detection tests** | Add tests with French, German, and Chinese threat phrases to `SemanticDetectorBaseTests` and at least two semantic detectors — confirms the embedding layer is truly language-agnostic and catches future regressions if example phrases accidentally become language-specific |
| **Semantic detector e2e benchmark with simulated latency** | `PipelineBenchmarks` already has `WithSemanticDetectionSimulated()` (10 ms per embedding). Add a `WithSemanticDetectionSimulated` variant to `E2EBenchmarks` and `SentinelPipelineBenchmarks` to measure full round-trip cost including intervention engine overhead on top of embedding latency |
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
