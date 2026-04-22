# AI.Sentinel

Security monitoring middleware for `IChatClient` ([Microsoft.Extensions.AI](https://learn.microsoft.com/en-us/dotnet/ai/microsoft-extensions-ai)). Wraps any LLM client transparently, scans every prompt and response through 45 detectors, and blocks, alerts, or logs threats — with an embedded real-time dashboard.

---

## Why you need it

When you connect an LLM to your application you inherit a new attack surface. Users can craft messages that override the model's instructions (**prompt injection**), the model can leak credentials or PII it saw in context (**credential exposure**), or return fabricated citations and wildly inconsistent numbers (**hallucination**). None of these are bugs in your code — they happen at the model boundary, which your existing middleware stack doesn't see.

AI.Sentinel sits at that boundary:

```
User prompt → [AI.Sentinel: scan] → LLM → [AI.Sentinel: scan] → Your app
```

It scans both directions on every call. If something looks wrong it can quarantine the message before it reaches the model, or quarantine the response before it reaches the user. If it only looks suspicious it alerts your logging/event system. Everything is stored in an in-process audit ring buffer and surfaced on a live dashboard.

---

## Packages

| Package | Description |
|---|---|
| `AI.Sentinel` | Core — pipeline, 45 detectors, intervention engine, audit store |
| `AI.Sentinel.AspNetCore` | Embedded dashboard (no JS framework, HTMX + SSE) |
| `AI.Sentinel.Cli` | `dotnet tool install AI.Sentinel.Cli` — offline replay CLI for forensics + CI |

```
dotnet add package AI.Sentinel
dotnet add package AI.Sentinel.AspNetCore   # optional, for the dashboard
```

---

## Quick start

```csharp
// Program.cs
builder.Services.AddAISentinel(opts =>
{
    opts.OnCritical = SentinelAction.Quarantine; // throw SentinelException
    opts.OnHigh     = SentinelAction.Alert;      // publish mediator notification
    opts.OnMedium   = SentinelAction.Log;
    opts.OnLow      = SentinelAction.Log;
});

builder.Services.AddChatClient(pipeline =>
    pipeline.UseAISentinel()
            .Use(new OpenAIChatClient(...)));

// optional dashboard
app.UseAISentinel("/ai-sentinel");
```

Catch quarantined messages:

```csharp
try
{
    var response = await chatClient.GetResponseAsync(messages);
}
catch (SentinelException ex)
{
    // ex.PipelineResult has the full detection details
    logger.LogWarning("Blocked: {Severity}", ex.PipelineResult?.MaxSeverity);
}
```

---

## How it works

Every call to `GetResponseAsync` or `GetStreamingResponseAsync` runs two pipeline passes:

1. **Prompt scan** — before the request reaches the LLM
2. **Response scan** — after the LLM responds, before the result is returned

Each pass runs all enabled detectors in parallel (`Task.WhenAll`), aggregates a **Threat Risk Score** (0–100), and calls the **Intervention Engine** which takes the configured action for the highest severity found.

```
IChatClient.GetResponseAsync(messages)
  │
  ├─ [1] DetectionPipeline.RunAsync(prompt context)
  │       ├─ PromptInjectionDetector
  │       ├─ JailbreakDetector
  │       ├─ ... (28 more, parallel)
  │       └─ ThreatRiskScore + detections
  │
  ├─ InterventionEngine.Apply(result)   → Quarantine / Alert / Log / PassThrough
  ├─ AuditStore.AppendAsync(entry)
  │
  ├─ inner IChatClient.GetResponseAsync(messages)
  │
  ├─ [2] DetectionPipeline.RunAsync(response context)
  ├─ InterventionEngine.Apply(result)
  └─ AuditStore.AppendAsync(entry)
```

---

## Detectors (45)

Detectors run in two modes:

- **Rule-based** — fast regex or heuristic, always active, sub-microsecond per call
- **LLM escalation** — fires a second-pass LLM classifier when a rule-based result hits `Medium`+, or when the detector has no rule-based path (stub detectors, active only with `opts.EscalationClient`)

### Security (25)

| ID | Detector | Type | Detects |
|---|---|---|---|
| SEC-01 | PromptInjection | Rule-based | Override/injection phrase patterns (`ignore all previous instructions`, `you are now a different AI`, etc.) |
| SEC-02 | CredentialExposure | Rule-based | API keys, tokens, private keys, secrets in output |
| SEC-03 | ToolPoisoning | Rule-based | Suspicious tool-call manipulation patterns |
| SEC-04 | DataExfiltration | Rule-based | Base64 blobs, high-entropy encoded data |
| SEC-05 | Jailbreak | Rule-based | Jailbreak attempt phrases (DAN, roleplay exploits) |
| SEC-06 | PrivilegeEscalation | Rule-based | Role/permission escalation requests |
| SEC-07 | CovertChannel | LLM escalation | Encoding-based hidden payloads |
| SEC-08 | EntropyCovertChannel | LLM escalation | Statistical entropy anomalies in output |
| SEC-09 | IndirectInjection | LLM escalation | Injection via retrieved documents or tool results |
| SEC-10 | AgentImpersonation | LLM escalation | Model claiming to be a different agent or system |
| SEC-11 | MemoryCorruption | LLM escalation | Attempts to corrupt agent memory/context |
| SEC-12 | UnauthorizedAccess | LLM escalation | Attempts to access restricted resources |
| SEC-13 | ShadowServer | LLM escalation | Redirection to unauthorised endpoints |
| SEC-14 | InformationFlow | LLM escalation | Cross-context data leakage |
| SEC-15 | PhantomCitationSecurity | LLM escalation | Security-context hallucinated authority sources |
| SEC-16 | GovernanceGap | LLM escalation | Policy/compliance bypass attempts |
| SEC-17 | SupplyChainPoisoning | LLM escalation | Compromised dependency suggestions |
| SEC-20 | SystemPromptLeakage | Rule-based | Verbatim fragments of the system prompt echoed in conversation history |
| SEC-23 | PiiLeakage | Rule-based | PII: SSN, credit card, IBAN, BSN, UK NINO, passport, DE tax ID, email+name, phone, DOB |
| SEC-24 | AdversarialUnicode | Rule-based | Zero-width spaces, homoglyphs, invisible characters used to smuggle hidden instructions |
| SEC-25 | CodeInjection | Rule-based | SQL injection, shell metacharacters, path traversal in LLM-generated code |
| SEC-26 | PromptTemplateLeakage | Rule-based | `{{variable}}`, `<SYSTEM>`, `[INST]` and other prompt scaffolding markers |
| SEC-27 | LanguageSwitchAttack | Rule-based | Abrupt script/language switch mid-response — injection vector via non-Latin text |
| SEC-28 | RefusalBypass | Rule-based | Model complied with a request it should have refused (caller-supplied forbidden patterns) |
| SEC-29 | OutputSchema | Rule-based | Response doesn't deserialize as the caller-supplied `ExpectedResponseType` (OWASP LLM05) |

### Hallucination (8)

| ID | Detector | Type | Detects |
|---|---|---|---|
| HAL-01 | PhantomCitation | Rule-based | Fake DOIs, arXiv IDs, `.invalid`/`.nonexistent` domains |
| HAL-02 | SelfConsistency | Rule-based | Numeric inconsistency (values differing by >10×) |
| HAL-03 | CrossAgentContradiction | LLM escalation | Contradictions between agents in a multi-agent session |
| HAL-04 | SourceGrounding | LLM escalation | Claims unsupported by provided context |
| HAL-05 | ConfidenceDecay | LLM escalation | Confidence degradation across turns |
| HAL-06 | StaleKnowledge | Rule-based | Time-sensitive facts stated as current ("the latest version is X", "the current CEO is Y") |
| HAL-07 | IntraSessionContradiction | LLM escalation | Model contradicts itself within the same conversation |
| HAL-08 | GroundlessStatistic | Rule-based | Specific percentages or statistics asserted without any source in the provided context |

### Operational (12)

| ID | Detector | Type | Detects |
|---|---|---|---|
| OPS-01 | BlankResponse | Rule-based | Empty or whitespace-only responses |
| OPS-02 | RepetitionLoop | Rule-based | Same sentence repeated 3+ times |
| OPS-03 | IncompleteCodeBlock | Rule-based | Unclosed code fences |
| OPS-04 | PlaceholderText | Rule-based | `TODO`, `[INSERT HERE]`, `Lorem ipsum` leftovers |
| OPS-05 | ContextCollapse | LLM escalation | Loss of conversational context across turns |
| OPS-06 | AgentProbing | LLM escalation | Attempts to map agent capabilities or system prompt |
| OPS-07 | QueryIntent | LLM escalation | Malicious intent hidden in benign-looking queries |
| OPS-08 | ResponseCoherence | LLM escalation | Response that doesn't address the question asked |
| OPS-12 | SemanticRepetition | LLM escalation | Same idea restated with different wording — extends RepetitionLoop beyond literal string matching |
| OPS-13 | PersonaDrift | LLM escalation | Model's tone, persona, or stated identity shifts significantly across turns — context poisoning signal |
| OPS-14 | Sycophancy | LLM escalation | Model reverses a stated position purely because the user pushed back — epistemic cowardice |
| OPS-15 | WrongLanguage | Rule-based | Response language doesn't match the user's language (script/charset detection) |

> **LLM escalation detectors** are no-ops until `opts.EscalationClient` is configured. Set it to a cheap fast model (e.g. GPT-4o-mini) to activate them without adding significant latency on the clean path — the second-pass only fires when the rule-based result is `Medium`+.

> **Streaming**: `GetStreamingResponseAsync` buffers the complete response before yielding tokens so the response scan can quarantine before any token reaches the application. Time-to-first-token equals full model response latency on this path.

---

## Configuration

```csharp
builder.Services.AddAISentinel(opts =>
{
    // Action per severity level
    opts.OnCritical = SentinelAction.Quarantine;  // throws SentinelException
    opts.OnHigh     = SentinelAction.Alert;        // publishes mediator notification + alert sink
    opts.OnMedium   = SentinelAction.Log;          // logs via ILogger
    opts.OnLow      = SentinelAction.Log;
    // opts.OnLow   = SentinelAction.PassThrough;  // silent

    // Optional: LLM second-pass classifier (activates 18 stub detectors)
    opts.EscalationClient = new OpenAIChatClient("gpt-4o-mini", ...);

    // Audit ring buffer size (in-process, no external store required)
    opts.AuditCapacity = 10_000; // default

    // Agent identity labels for audit entries
    opts.DefaultSenderId   = new AgentId("web-user");
    opts.DefaultReceiverId = new AgentId("assistant");

    // Optional: POST alert payloads to a webhook on Quarantine/Alert actions
    opts.AlertWebhook = new Uri("https://hooks.example.com/sentinel");

    // Optional: suppress repeat alerts for the same detector+session.
    // null (default) suppresses for the entire session lifetime.
    // Set a TimeSpan to re-alert after the window expires.
    opts.AlertDeduplicationWindow = TimeSpan.FromMinutes(5);

    // Optional: per-session token-bucket circuit breaker.
    // MaxCallsPerSecond = steady-state refill rate; BurstSize = initial token count.
    // Pass "sentinel.session_id" in ChatOptions.AdditionalProperties for per-user buckets.
    // Without a session key, all calls share a global bucket.
    opts.MaxCallsPerSecond = 5;   // allow 5 calls/sec per session (steady state)
    opts.BurstSize = 20;          // up-front burst before throttling kicks in

    // Optional: validate structured LLM responses against a caller-supplied type (SEC-29).
    // The type must be annotated with [ZeroAllocSerializable(SerializationFormat.SystemTextJson)].
    // Requires calling services.AddSerializerDispatcher() (from ZeroAlloc.Serialisation).
    opts.ExpectedResponseType = typeof(MyResponse);
});
```

### Actions

| `SentinelAction` | Behaviour |
|---|---|
| `Quarantine` | Throws `SentinelException` with full `PipelineResult`. Stops the call. Also fires the alert sink. |
| `Alert` | Publishes `ThreatDetectedNotification` + `InterventionAppliedNotification` via `IMediator`. Fires the alert sink. Call continues. |
| `Log` | Writes to `ILogger<InterventionEngine>`. Call continues. |
| `PassThrough` | No action. Detections are still audited. |

Alert sink behaviour: when `opts.AlertWebhook` is set, `WebhookAlertSink` POSTs a JSON payload (type, severity, detector, reason, action, session) to the configured URL on `Quarantine` or `Alert` actions. The `DeduplicatingAlertSink` wraps the webhook sink and suppresses repeat alerts for the same detector+session, controlled by `opts.AlertDeduplicationWindow`.

---

## Dashboard

Mount the built-in dashboard with one line:

```csharp
app.UseAISentinel("/ai-sentinel");

// Protect it with your own middleware:
app.UseAISentinel("/ai-sentinel", branch =>
    branch.Use(RequireInternalNetwork));
```

The dashboard shows:
- **Threat Risk Score** — live ring gauge (0–100, SAFE / WATCH / ALERT / ISOLATE)
- **Live event feed** — every detection with severity badge, detector ID, and reason
- **Detector hit stats** — which detectors fire most

No npm, no JS build step — served entirely from embedded resources using HTMX + SSE.

---

## Events / Mediator integration

If your DI container has an `IMediator` (ZeroAlloc.Mediator, MediatR-compatible), AI.Sentinel publishes two notification types on `Alert`-level events:

```csharp
// Fired when a threat is detected
readonly record struct ThreatDetectedNotification(
    SessionId      SessionId,
    AgentId        SenderId,
    AgentId        ReceiverId,
    PipelineResult PipelineResult,
    DateTimeOffset DetectedAt);

// Fired when an intervention is applied
readonly record struct InterventionAppliedNotification(
    SessionId      SessionId,
    SentinelAction Action,
    Severity       Severity,
    string         Reason,
    DateTimeOffset AppliedAt);
```

Register a handler to forward these to Slack, PagerDuty, your SIEM, or anywhere else.

---

## CLI: `sentinel` (offline replay)

`AI.Sentinel.Cli` is a `dotnet tool` that replays saved conversations through the full detector pipeline — useful for incident forensics, CI regression testing, and detector tuning.

```
dotnet tool install -g AI.Sentinel.Cli
sentinel scan conversation.json
```

Accepts OpenAI Chat Completion JSON (`{"messages": [...]}`) or AI.Sentinel audit NDJSON. Auto-detects by default.

```
sentinel scan conversation.json
  [--format <openai|audit|auto>]                 # default: auto
  [--output <text|json>]                          # default: text
  [--expect <detectorId>]                         # repeatable, e.g. --expect SEC-01
  [--min-severity <Low|Medium|High|Critical>]
  [--baseline <prior-result.json>]                # diff against a prior run
```

Exit codes: `0` scan completed (no failing assertions), `1` assertion failed or baseline regression, `2` I/O or parse error.

The CLI's core types — `SentinelReplayClient`, `ConversationLoader`, `ReplayRunner`, `ReplayResult` — are all `public`, so callers can reference `AI.Sentinel.Cli` programmatically from their own xUnit tests to assert detection behavior on saved conversations.

---

## OpenTelemetry

AI.Sentinel emits metrics and traces out of the box via the `ai.sentinel` meter and activity source. Wire them into your existing OTel pipeline with the standard .NET instrumentation API:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddMeter("ai.sentinel"))
    .WithTracing(t => t.AddSource("ai.sentinel"));
```

**Metrics**

| Metric | Type | Description |
|---|---|---|
| `sentinel.scans` | Counter | Total pipeline scans executed |
| `sentinel.scan.ms` | Histogram | Pipeline scan duration in milliseconds |
| `sentinel.threats` | Counter | Threats detected (tagged by `severity` and `detector`) |
| `sentinel.alerts.suppressed` | Counter | Alerts suppressed by the deduplication window (tagged by `detector`) |
| `sentinel.rate_limit.exceeded` | Counter | Calls rejected by the per-session rate limiter (tagged by `session`) |

**Traces**

Each `GetResponseAsync` / `GetStreamingResponseAsync` call produces a `sentinel.scan` span (one per direction — prompt and response) with the following attributes:

| Attribute | Description |
|---|---|
| `sentinel.severity` | Max severity found in this scan |
| `sentinel.is_clean` | `true` when no threats were detected |
| `sentinel.threat_count` | Number of distinct detector hits |
| `sentinel.top_detector` | ID of the highest-severity detector that fired |

All metrics and spans are zero-cost when no listener is registered — there is no overhead when OTel is not configured.

---

## Audit store

All detections (regardless of severity) are written to a **ring buffer audit store** in process memory. Capacity defaults to 10,000 entries; oldest entries are overwritten when full.

Query the store directly:

```csharp
var store = app.Services.GetRequiredService<IAuditStore>();

await foreach (var entry in store.QueryAsync(new AuditQuery
{
    MinSeverity = Severity.Medium,
    From        = DateTimeOffset.UtcNow.AddHours(-1),
    PageSize    = 100
}, CancellationToken.None))
{
    Console.WriteLine($"{entry.Timestamp:HH:mm:ss} [{entry.Severity}] {entry.DetectorId}: {entry.Reason}");
}
```

---

## Benchmarks

All measurements: .NET 9.0.15, Windows 11, Release, `Job.Default`, `MemoryDiagnoser` + `ThreadingDiagnoser`.

**Individual detectors**

| Scenario | Mean | Allocated |
|---|---|---|
| `PromptInjection` — clean input | ~59 ns | 0 B |
| `PromptInjection` — malicious input | ~231 ns | 480 B |
| `RepetitionLoopDetector` — clean input | ~106 ns | 296 B |

**Detection pipeline** (`DetectionPipeline.RunAsync`, no-op inner client)

| Detector set | Input | Mean | Allocated |
|---|---|---|---|
| Empty (baseline) | clean | ~16 ns | 32 B |
| Security-only (9 detectors) | clean | ~958 ns | 472 B |
| Security-only (9 detectors) | malicious | ~2,388 ns | 2,616 B |
| All detectors (30 rule-based) | clean | ~1,855 ns | 1,568 B |
| All detectors (30 rule-based) | malicious | ~3,462 ns | 4,008 B |

**End-to-end** (`SentinelChatClient.GetResponseAsync`, no-op inner client, single short message)

| Detector set | Input | Mean | Allocated |
|---|---|---|---|
| Empty | clean | ~994 ns | 1.24 KB |
| Security-only | clean | ~2,636 ns | 2.26 KB |
| All detectors | clean | ~6,268 ns | 4.53 KB |
| All detectors | malicious | ~8,653 ns | 7.25 KB |

**Audit store**

| Scenario | Mean | Allocated |
|---|---|---|
| Sequential append | ~118 ns | 0 B |
| 8 concurrent appends | ~1,468 ns | 400 B |

> E2E numbers exclude real LLM latency (measured against a no-op inner client). Add your model's round-trip time on top.

Run the full suite yourself:

```bash
dotnet run --project benchmarks/AI.Sentinel.Benchmarks -c Release -- --filter "*"
```

---

## License

MIT © ZeroAlloc-Net
