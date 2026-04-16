# AI.Sentinel

Security monitoring middleware for `IChatClient` ([Microsoft.Extensions.AI](https://learn.microsoft.com/en-us/dotnet/ai/microsoft-extensions-ai)). Wraps any LLM client transparently, scans every prompt and response through 30 detectors, and blocks, alerts, or logs threats — with an embedded real-time dashboard.

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
| `AI.Sentinel` | Core — pipeline, 30 detectors, intervention engine, audit store |
| `AI.Sentinel.AspNetCore` | Embedded dashboard (no JS framework, HTMX + SSE) |

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

## Detectors (30)

Detectors run in two modes:

- **Rule-based** — fast regex or heuristic, always active, sub-microsecond per call
- **LLM escalation** — fires a second-pass LLM classifier when a rule-based result hits `Medium`+, or when the detector has no rule-based path (stub detectors, active only with `opts.EscalationClient`)

### Security (17)

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

### Hallucination (5)

| ID | Detector | Type | Detects |
|---|---|---|---|
| HAL-01 | PhantomCitation | Rule-based | Fake DOIs, arXiv IDs, `.invalid`/`.nonexistent` domains |
| HAL-02 | SelfConsistency | Rule-based | Numeric inconsistency (values differing by >10×) |
| HAL-03 | CrossAgentContradiction | LLM escalation | Contradictions between agents in a multi-agent session |
| HAL-04 | SourceGrounding | LLM escalation | Claims unsupported by provided context |
| HAL-05 | ConfidenceDecay | LLM escalation | Confidence degradation across turns |

### Operational (8)

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

> **LLM escalation detectors** are no-ops until `opts.EscalationClient` is configured. Set it to a cheap fast model (e.g. GPT-4o-mini) to activate them without adding significant latency on the clean path — the second-pass only fires when the rule-based result is `Medium`+.

---

## Configuration

```csharp
builder.Services.AddAISentinel(opts =>
{
    // Action per severity level
    opts.OnCritical = SentinelAction.Quarantine;  // throws SentinelException
    opts.OnHigh     = SentinelAction.Alert;        // publishes mediator notification
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
});
```

### Actions

| `SentinelAction` | Behaviour |
|---|---|
| `Quarantine` | Throws `SentinelException` with full `PipelineResult`. Stops the call. |
| `Alert` | Publishes `ThreatDetectedNotification` + `InterventionAppliedNotification` via `IMediator`. Call continues. |
| `Log` | Writes to `ILogger<InterventionEngine>`. Call continues. |
| `PassThrough` | No action. Detections are still audited. |

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
record ThreatDetectedNotification(
    SessionId      Session,
    AgentId        Sender,
    AgentId        Receiver,
    PipelineResult Result,
    DateTimeOffset Timestamp);

// Fired when an intervention is applied
record InterventionAppliedNotification(
    SessionId      Session,
    SentinelAction Action,
    Severity       Severity,
    string         Reason,
    DateTimeOffset Timestamp);
```

Register a handler to forward these to Slack, PagerDuty, your SIEM, or anywhere else.

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

All measurements: .NET 9, Release, `Job.Default`, `MemoryDiagnoser` + `ThreadingDiagnoser`.

| Scenario | Mean | Allocated |
|---|---|---|
| Audit store — sequential append | ~64 ns | 0 B |
| Single regex detector — clean input | ~36 ns | 0 B |
| Single regex detector — malicious input | ~237 ns | ~480 B |
| `RepetitionLoopDetector` — clean input | ~246 ns | ~296 B |
| Audit store — 8 concurrent appends | ~731 ns | 400 B |

Run the full suite yourself:

```bash
dotnet run --project benchmarks/AI.Sentinel.Benchmarks -c Release -- --filter "*"
```

---

## License

MIT © ZeroAlloc-Net
