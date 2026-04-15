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

**Security (17):** 6 rule-based + 11 LLM-escalation-only

| Detector | Type | Description |
|---|---|---|
| `SEC-01` PromptInjection | Rule-based | Override/injection phrase patterns |
| `SEC-02` CredentialExposure | Rule-based | API keys, tokens, private keys in output |
| `SEC-03` ToolPoisoning | Rule-based | Suspicious tool-call patterns |
| `SEC-04` DataExfiltration | Rule-based | Base64 / high-entropy data patterns |
| `SEC-05` Jailbreak | Rule-based | Jailbreak attempt phrases |
| `SEC-06` PrivilegeEscalation | Rule-based | Role/permission escalation phrases |
| `SEC-07`–`SEC-17` (11 detectors) | LLM escalation only | Covert channels, agent impersonation, supply chain, indirect injection, etc. Rule-based pass returns Clean; LLM second-pass fires when `opts.EscalationClient` is configured. |

**Hallucination (5):** PhantomCitation and SelfConsistency are rule-based; CrossAgentContradiction, SourceGrounding, and ConfidenceDecay are LLM-escalation-only.

**Operational (8):** BlankResponse, RepetitionLoop, IncompleteCodeBlock, PlaceholderText are rule-based; ContextCollapse, AgentProbing, QueryIntent, ResponseCoherence are LLM-escalation-only.

> **v0.1.0 note:** LLM-escalation-only detectors provide no protection without `opts.EscalationClient`. They intentionally skip the rule-based fast path — the LLM classifier is the detection mechanism. Configure `EscalationClient` to activate them.

## Hybrid Detection

Rule-based fast path for all 25 detectors. Detectors that implement `ILlmEscalatingDetector` optionally fire a second-pass LLM classifier when the rule-based result is `Medium` or higher — keeping costs low while catching subtle threats.

## Dashboard

Embedded Razor-free dashboard served via `app.UseAISentinel()`. No npm, no JS framework — HTMX polling + SSE.

- Threat Risk Score ring gauge (0-100, SAFE/WATCH/ALERT/ISOLATE)
- Live event feed with severity badges
- Detector hit stats

## License

MIT
