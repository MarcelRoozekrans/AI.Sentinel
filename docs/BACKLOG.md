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
| OPS-12 | `SemanticRepetitionDetector` | Same idea restated with different wording — extends `RepetitionLoop` beyond literal string matching; LLM escalation |
| OPS-13 | `PersonaDriftDetector` | Model's tone, persona, or stated identity shifts significantly across turns within a session — early signal of context poisoning |
| OPS-14 | `SycophancyDetector` | Model changes its stated facts or reverses a position purely because the user pushed back — epistemic cowardice as a reliability signal |
| OPS-15 | `WrongLanguageDetector` | Response language doesn't match the user's language — rule-based via script/charset detection |

### Security

| ID (proposed) | Name | What it detects |
|---|---|---|
| SEC-18 | `ToolDescriptionDivergenceDetector` | Tool description observed at invocation differs from description at discovery — possible MCP supply-chain manipulation |
| SEC-19 | `ToolCallFrequencyDetector` | Anomalous spike or unusual pattern in tool invocation rate within a session — possible automated exfiltration or resource abuse |
| SEC-20 | `SystemPromptLeakageDetector` | Response contains verbatim fragments of the system prompt — model was manipulated into disclosing its instructions (cf. OWASP LLM07) |
| SEC-21 | `ExcessiveAgencyDetector` | Model takes unsolicited autonomous actions (file writes, API calls, spawning agents) beyond its stated scope (cf. OWASP LLM06 / ASI02) |
| SEC-22 | `HumanTrustManipulationDetector` | Model output attempts to build false rapport, impersonate an authority figure, or exploit human-agent trust to bypass oversight (cf. OWASP ASI09) |
| SEC-23 | `PiiLeakageDetector` | PII in responses: name+address combos, SSNs, phone numbers, DOBs — distinct from `CredentialExposure` which targets secrets/keys |
| SEC-24 | `AdversarialUnicodeDetector` | Zero-width spaces, homoglyphs, invisible characters used to smuggle hidden instructions past rule-based filters |
| SEC-25 | `CodeInjectionDetector` | SQL injection, shell metacharacters, path traversal in LLM-generated code — model as injection vector into downstream systems |
| SEC-26 | `PromptTemplateLeakageDetector` | Model reveals `{{variable}}`, `<SYSTEM>`, or other prompt scaffolding — confirms system prompt structure to an attacker |
| SEC-27 | `LanguageSwitchAttackDetector` | Model abruptly switches language mid-response — common vector for injections embedded in non-English text that bypassed rule-based filters |
| SEC-28 | `RefusalBypassDetector` | Model complied with a request it should have refused — requires caller-supplied forbidden topic patterns; measures silent policy violations |

### Hallucination

| ID (proposed) | Name | What it detects |
|---|---|---|
| HAL-06 | `StaleKnowledgeDetector` | Model states time-sensitive facts as current ("the latest version is X", "the current CEO is Y") — rule-based on date/currency phrases, LLM escalation to verify |
| HAL-07 | `IntraSessionContradictionDetector` | Model contradicts itself within the same conversation — distinct from `CrossAgentContradiction` which spans agents |
| HAL-08 | `GroundlessStatisticDetector` | Specific percentages or statistics asserted without any source in the provided context (e.g. "studies show 73% of...") |

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

## Architecture / Integration

| Feature | Description |
|---|---|
| **Claude Code hook adapter** | `AI.Sentinel.ClaudeCode` package — emit `PreToolUse` / `PostToolUse` hook payloads from the audit store so Claude Code can block or annotate tool calls in the IDE |
| **Multi-agent spawn-chain tracking** | Propagate a `TraceId` through nested `SentinelChatClient` instances so the audit store records a parent→child call graph. Enables cross-agent contradiction and uncertainty propagation detection. |
| **Session behavioral signatures** | Derive a compact fingerprint per session (tool call distribution, message length variance, vocabulary entropy) for anomaly scoring against a rolling baseline |
| **Streaming pipeline support** | Run detector passes on `GetStreamingResponseAsync` — currently only `GetResponseAsync` is scanned |
| **Output schema validation** | Validate structured (JSON/XML) responses against a caller-supplied schema before returning to the application — catches malformed outputs and prompt-injected schema violations (cf. OWASP LLM05) |
| **Per-session rate limiting** | Circuit breaker that triggers `SentinelAction` when call rate within a session window exceeds a configurable threshold — guards against token-budget exhaustion and automated enumeration attacks (cf. OWASP LLM10) |
| **OpenTelemetry integration** | Emit an `Activity` span per pipeline run with detector results as span attributes, and a `Meter` for threat rate/severity distribution — plugs into existing OTel infrastructure with zero config |
| **Persistent audit store** | Pluggable `IAuditStore` interface backed by SQLite, Postgres, or any sink — in-memory ring buffer remains the default, no breaking change |
| **Webhook / alert sinks** | Push `ThreatDetectedNotification` to Slack, PagerDuty, or generic webhooks without requiring MediatR consumers — configured via `opts.AlertSinks` |
| **Custom detector SDK** | Official public API (`ISentinelDetector`) + stable NuGet surface for registering third-party detectors via `opts.AddDetector<T>()` |
| **Per-pipeline configuration** | Register multiple named `SentinelOptions` instances so different endpoints get different detector sets, thresholds, or `EscalationClient`s |
| **Offline replay / test harness** | `SentinelReplayClient` that feeds a saved conversation JSON through the pipeline without a real LLM — useful for regression testing detector changes and incident forensics |
| **Alert deduplication** | Suppress repeat alerts for the same detector+session within a configurable time window — prevents alert fatigue when a session repeatedly triggers the same pattern |
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
| **`sentinel` CLI tool** | `dotnet tool install AI.Sentinel.Cli` → `sentinel scan conversation.json` — run the detector pipeline offline against saved chat files, useful for incident forensics and CI |
| **Detector test helpers** | `SentinelTestBuilder.WithPrompt(...).ExpectDetection<T>(Severity.High)` — xUnit/NUnit-friendly fluent API for unit-testing detectors with known inputs |
| **Benchmark CI gate** | MSBuild target that runs the benchmark suite and fails the build if any detector regresses past a configurable latency threshold |
| **`AI.Sentinel.Analyzers`** | Roslyn diagnostic package that catches misconfiguration at build time: warn when `EscalationClient` is unset but LLM-escalation detectors are active, warn when `OnCritical = PassThrough`, warn on zero audit capacity |
| **Source-generated detector registration** | `[SentinelDetector]` attribute on a custom detector class → source generator emits the `opts.AddDetector<T>()` call — complements the custom detector SDK with zero-boilerplate registration |
| **EditorConfig blank-line rule** | Add an `.editorconfig` rule enforcing a blank line between `using` directives and `namespace` declarations — currently inconsistent across detector files and will widen without enforcement |
| **`SentinelPipeline` direct benchmark** | Add a `SentinelPipelineBenchmarks` class measuring `GetResponseResultAsync` directly (not via the `SentinelChatClient` shim) — gives a clean baseline for the Result-returning path independent of the IChatClient exception-mapping overhead |

---

## ZeroAlloc Integration (`AI.Sentinel.ZeroAlloc`)

Optional package that wires ZeroAlloc ecosystem packages into AI.Sentinel hot paths for measurably lower allocations. All items are additive — the core package has no ZeroAlloc dependency.

| Feature | ZeroAlloc Package | Description |
|---|---|---|
| **Zero-alloc audit ring buffer** | `ZeroAlloc.Collections` | Replace the current `ConcurrentQueue`-backed ring buffer with `ZeroAlloc.Collections.RingBuffer<T>` — ArrayPool-backed, no per-entry allocation |
| **Typed `SessionId` / `AgentId`** | `ZeroAlloc.ValueObjects` `[TypedId]` | Replace `string`-based identifiers with source-generated `readonly record struct` typed IDs — zero boxing on hot paths, EF Core and JSON converters included |
| **OTel spans via `[Instrument]`** | `ZeroAlloc.Telemetry` | Apply `[Instrument]` to `IAuditStore` and `IDetectionPipeline` — generator emits static `ActivitySource` / `Meter` fields with no `params object[]` boxing |
| **Rate limiting via `[RateLimit]`** | `ZeroAlloc.Resilience` | Implement per-session rate limiting with a lock-free token bucket generated by `ZeroAlloc.Resilience` instead of a hand-rolled `Interlocked` counter |
| **FSM-modeled agent action sequences** | `ZeroAlloc.StateMachine` | Power `ExcessiveAgencyDetector` with a source-generated FSM — declare allowed tool-call sequences as states/transitions; any deviation triggers a detection |
| **Compile-time DI registration** | `ZeroAlloc.Inject` | Replace reflection-based detector scanning with `[Transient]`-attributed detectors and a generated `AddAISentinelDetectors()` extension method |
| **NDJSON export mapping** | `ZeroAlloc.Mapping` | Generate `AuditEntry → ExportDto` mapping with `[Map<AuditEntry, AuditExportDto>]` — used by the dashboard export endpoint, zero reflection |
| **Mediator authorization for prompts** | `ZeroAlloc.Mediator.Authorization` | Gate prompt dispatch on caller-declared policies via `[Authorize("policy")]` on the mediator request — enforces access control at the model boundary |
| **Fluxor state management in ChatApp** | `ZeroAlloc.Fluxor` | Replace ad-hoc component state in `ChatApp.Client/Chat.razor` with a compile-time Flux store — `ChatState` (messages, connection status, active threats) as a `readonly record struct`, reducers for `MessageSentAction`, `TokenReceivedAction`, `ThreatDetectedAction`; demonstrates ZeroAlloc.Fluxor + AI.Sentinel integration end-to-end. _Conditional on ZeroAlloc.Fluxor shipping._ |
