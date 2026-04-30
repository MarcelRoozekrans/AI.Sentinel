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
| **`ZeroAlloc.Authorization.Abstractions` extraction** | Once `ZeroAlloc.Mediator.Authorization` ships, extract `ISecurityContext` / `IAuthorizationPolicy` / `[Authorize]` / `[AuthorizationPolicy]` into a shared package so AI.Sentinel and ZeroAlloc.Mediator share primitives. One `IAuthorizationPolicy` class works for both worlds. |
| **Async `IAuthorizationPolicy`** | Add `Task<bool> IsAuthorizedAsync(ISecurityContext)` overload. Coordinate with ZeroAlloc.Mediator.Authorization design before changing the interface. |
| **Source-gen-driven policy name lookup** | Replace startup reflection scan in `DefaultToolCallGuard` registration with a generated `name → factory` table. Cold-start performance optimisation. |
| **Policy timeout** | `opts.PolicyTimeout` with deny-on-timeout for I/O-bound policies (tenant lookup, etc.). |
| **`opts.AuditAllows`** | Opt-in compliance mode that also audits Allow decisions. |
| **`[Authorize]` attribute discovery for AIFunction-bound methods** | Translate method-level `[Authorize("policy")]` to a `RequireToolPolicy(funcName, "policy")` binding at AIFunction registration time. (Deferred from Task 8 to keep the in-process surface scope tight.) |
| **Localized hardening bundle** | `SentinelOptions.SystemPrefixes` keyed by culture code with a simple language-detection step + fallback. Lifts `SystemPrefix` from English-only to multilingual. Future-additive — current single-string property remains the default. Driven by a real customer asking for non-English support. |

---

## Architecture / Integration

| Feature | Description |
|---|---|
| **MCP proxy: SseClientTransport** | The older SSE-only transport. Defer until a real user reports needing it; spec direction is StreamableHttp (now supported via `HttpClientTransport` in `AutoDetect` mode, which falls back to SSE automatically when the target only speaks SSE). |
| **MCP proxy: per-request timeout** | Different concern from the v1.1 subprocess shutdown grace. The SDK already supports `CancellationToken` per call; add a Sentinel-side per-call timeout (env-var configurable) if a user reports hung in-flight requests. |
| **MCP proxy: OAuth2 / mTLS auth for HTTP transport** | `SENTINEL_MCP_HTTP_HEADERS` covers static-token auth out of the box. OAuth client-credentials flow and client-certificate (mTLS) auth are their own design — token refresh, cert store integration, and config surface need shaping before implementation. |
| **MCP proxy: SIGKILL on subprocess shutdown grace expiry** | v1.1 logs `transport_dispose action=grace_expired` when the upstream child blows past `SENTINEL_MCP_TIMEOUT_SEC`, but the proxy doesn't actually kill the process — `StdioClientTransport` doesn't expose its `Process`. Wrap the SDK transport (or shell out) to capture the PID and `Kill(entireProcessTree: true)` on grace expiry. |
| **Multi-agent spawn-chain tracking** | Propagate a `TraceId` through nested `SentinelChatClient` instances so the audit store records a parent→child call graph. Enables cross-agent contradiction and uncertainty propagation detection. |
| **Session behavioral signatures** | Derive a compact fingerprint per session (tool call distribution, message length variance, vocabulary entropy) for anomaly scoring against a rolling baseline |
| **`AI.Sentinel.Postgres`** | Server-grade audit store for multi-instance deployments. Same `IAuditStore` interface, Postgres backend with appropriate schema + connection pooling. Defer until a real customer asks. |
| **`SplunkHecAuditForwarder`** | Direct Splunk HTTP Event Collector forwarder (alternative to OpenTelemetry-via-collector path). Simpler for Splunk-only shops; a redundant path for users with OTel collectors. |
| **`GenericWebhookAuditForwarder`** | Operator-defined POST endpoint with template payload for arbitrary HTTP integrations not covered by NDJSON / Azure Sentinel / OpenTelemetry. |
| **NDJSON file rotation** | In-process rotation of `NdjsonFileAuditForwarder` output by size or time window. Today operators handle rotation externally (logrotate / Vector / Fluent Bit). |
| **Live integration test for `AzureSentinelAuditForwarder`** | Gated on a CI secret with a real Sentinel workspace + DCR. Validates DCR setup + Logs Ingestion round-trip end-to-end. Out of scope for unit tests. |
| **Live OpenTelemetry collector integration test** | Docker-Compose-spun-up OTel collector + verify round-trip from `OpenTelemetryAuditForwarder` through the collector to a stub backend. Out of scope for unit tests. |
| **`BufferingAuditForwarder` configurable per registration** | Today `AddSentinelAzureSentinelForwarder` uses default buffering options (batch=100, interval=5s). Add a `.WithBuffering(maxBatch, maxInterval)` builder pattern so operators can tune for their SIEM's ingestion rate limits. |
| **Detector result caching** | Short-TTL cache keyed on content hash — avoids re-running all detectors when identical prompts are sent in quick succession |

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
| **Detector ID prefix convention enforcement** | Roslyn analyzer that warns when a third-party detector class uses an ID prefix matching official ones (`SEC-`, `HAL-`, `OPS-`, `AUTHZ-`). Prevents collisions before they become support tickets. |
| **Public `StubDetector`** | Promote the internal `StubDetector` to public if a third party requests it. Currently used internally as a placeholder for not-yet-implemented detectors; not a 3rd-party need today. |
| **SemVer commitment for `AI.Sentinel.Detectors.Sdk`** | Formal stability policy once the project hits 1.0. Until then, "we'll try not to break minor versions" is the implicit contract. |
| **Sample app showcase: custom detector** | Extend `samples/ConsoleDemo/` with a `MyCustomDetector` registered via `opts.AddDetector<T>()` to make the SDK pattern discoverable through the existing samples surface. |
| **Multi-language detection tests** | Add tests with French, German, and Chinese threat phrases to `SemanticDetectorBaseTests` and at least two semantic detectors — confirms the embedding layer is truly language-agnostic and catches future regressions if example phrases accidentally become language-specific |
| **Semantic detector e2e benchmark with simulated latency** | `PipelineBenchmarks` already has `WithSemanticDetectionSimulated()` (10 ms per embedding). Add a `WithSemanticDetectionSimulated` variant to `E2EBenchmarks` and `SentinelPipelineBenchmarks` to measure full round-trip cost including intervention engine overhead on top of embedding latency |
| **Benchmark CI gate** | MSBuild target that runs the benchmark suite and fails the build if any detector regresses past a configurable latency threshold |
| **`AI.Sentinel.Analyzers`** | Roslyn diagnostic package that catches misconfiguration at build time: warn when `EscalationClient` is unset but LLM-escalation detectors are active, warn when `OnCritical = PassThrough`, warn on zero audit capacity |
| **`Configure<T>` startup warning for unmatched types** | Emit a startup warning when `opts.Configure<T>(...)` keys a `T` that is abstract, an interface (e.g., `Configure<IDetector>` or `Configure<SemanticDetectorBase>`), or never registered as a concrete detector. Today these silently no-op because the pipeline keys on `detector.GetType()`. Real footgun — operator's misconfiguration is invisible until they notice the detector still fires at default severity. Pair with a doc note. |
| **`DetectionResult` carries clamp-applied annotation** | When `Configure<T>` Floor/Cap rewrites a severity, the audit entry shows the clamped value but the original `Reason` string is preserved verbatim. Operators reading audit logs months later cannot distinguish "detector fired High" from "detector fired Low, Floor=High raised it". Either annotate `Reason` (e.g., append `" (clamped: Floor=High)"`) or carry a `ClampApplied`/`OriginalSeverity` field on `DetectionResult`. Observability gap for security audits. |
| **Per-pipeline configuration Phase B — request-time selector** | `services.AddAISentinel(Func<IServiceProvider, RequestContext, string> selector)` resolves which named pipeline to use per request. Solves multi-tenant SaaS where the tenant ID arrives with the request. Pairs with optional per-name audit isolation (`AddAISentinel("name", opts, audit: ...)` overrides). Phase A foundation already shipped. |
| **Per-pipeline auth bindings (`IToolCallGuard` per name)** | Today `opts.RequireToolPolicy(...)` calls on a named pipeline are silently ignored — only the default pipeline's bindings are consulted. README documents the limitation. Real fix: keyed `IToolCallGuard` per name + middleware that picks the right one. Likely bundled with Phase B request-time selector. |
| **Auto-register shared infrastructure on first named `AddAISentinel`** | Today `services.AddAISentinel("strict", ...)` without a default call leaves `IAuditStore`/`IAlertSink`/`IAuditForwarder` unregistered; `UseAISentinel("strict")` then throws a defensive error at chat-client construction. Cleaner: detect missing shared infra and auto-register defaults from the first named call's `SentinelOptions` (e.g., its `AuditCapacity`). Removes a silent footgun. |
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
