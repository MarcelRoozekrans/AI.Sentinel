# AI.Sentinel

Security monitoring middleware for `IChatClient` (Microsoft.Extensions.AI). Detects prompt injection, credential exposure, hallucinations, and operational anomalies in real time — with an embedded dashboard.

## Packages

| Package | Description |
|---|---|
| `AI.Sentinel` | Core middleware — 25 detectors, intervention engine, audit trail |
| `AI.Sentinel.AspNetCore` | Embedded dashboard at `/ai-sentinel` |

## Quick Start

```csharp
// Program.cs
builder.Services.AddAISentinel(opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.OnHigh     = SentinelAction.Alert;
});

builder.Services.AddChatClient(pipeline =>
    pipeline.UseAISentinel()
            .Use(new OpenAIChatClient(...)));

app.UseAISentinel("/ai-sentinel"); // dashboard
```

## Detectors (25)

**Security (17):** Prompt injection, credential exposure, tool poisoning, data exfiltration, jailbreak, privilege escalation, and more.

**Hallucination (5):** Phantom citations, cross-agent contradictions, source grounding, confidence decay, self-consistency.

**Operational (8):** Blank responses, repetition loops, incomplete code blocks, placeholder text, and more.

## Hybrid Detection

Rule-based fast path for all 25 detectors. Detectors that implement `ILlmEscalatingDetector` optionally fire a second-pass LLM classifier when the rule-based result is `Medium` or higher — keeping costs low while catching subtle threats.

## Dashboard

Embedded Razor-free dashboard served via `app.UseAISentinel()`. No npm, no JS framework — HTMX polling + SSE.

- Threat Risk Score ring gauge (0-100, SAFE/WATCH/ALERT/ISOLATE)
- Live event feed with severity badges
- Detector hit stats

## License

MIT
