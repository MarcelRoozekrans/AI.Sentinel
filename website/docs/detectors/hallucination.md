---
sidebar_position: 3
title: Hallucination detectors
---

# Hallucination detectors (9)

Hallucination detectors look for fabricated or unsupported content — phantom citations, made-up authorities, internal contradictions, stale knowledge stated as current, confidence degradation across turns, and over-eager agreement with user claims.

## Reference

| ID | Detector | Type | Detects |
|---|---|---|---|
| **HAL-01** | `PhantomCitationDetector` | Rule-based | Fake DOIs, arXiv IDs, `.invalid` / `.nonexistent` domains |
| **HAL-02** | `SelfConsistencyDetector` | Rule-based | Numeric inconsistency (values differing by >10×) |
| **HAL-03** | `CrossAgentContradictionDetector` | Semantic | Contradictions between agents in a multi-agent session |
| **HAL-04** | `SourceGroundingDetector` | Semantic | Claims unsupported by provided context |
| **HAL-05** | `ConfidenceDecayDetector` | Semantic | Confidence degradation across turns |
| **HAL-06** | `StaleKnowledgeDetector` | Semantic | Time-sensitive facts stated as current ("the latest version is X", "the current CEO is Y") |
| **HAL-07** | `IntraSessionContradictionDetector` | Semantic | Model contradicts itself within the same conversation |
| **HAL-08** | `GroundlessStatisticDetector` | Rule-based | Specific percentages / statistics asserted without any source in the provided context |
| **HAL-09** | `UncertaintyPropagationDetector` | Semantic | Hedged statements that contradict a definitive assertion in the same response |

## When these matter

Hallucinations are quieter than security threats — they don't typically trigger `Quarantine` because the response *looks* fine. They're best handled at `Alert` or `Log` severity:

```csharp
opts.OnHigh   = SentinelAction.Alert;   // route High hallucinations to ops dashboard
opts.OnMedium = SentinelAction.Log;     // log everything else for analysis
```

Pair the audit feed with downstream review tooling (manual spot-checks, structured grading, or feedback loops to fine-tuning data). The detectors flag *suspect* responses; humans decide whether to act.

## Source-grounding detector — context matters

`HAL-04 SourceGroundingDetector` expects the provided context (system prompt, retrieved documents, tool messages) to be embedded alongside the assistant message. If your context is empty or trivial, this detector will fire on every assertion. Best results come from:

- A non-empty system prompt
- Retrieved documents passed via tool messages or system instructions
- Multi-turn conversations where prior turns supply grounding

When you don't have grounding context — fully ungrounded chat-style usage — disable this detector:

```csharp
opts.Configure<SourceGroundingDetector>(c => c.Enabled = false);
```

## Stale knowledge — date-sensitive

`HAL-06 StaleKnowledgeDetector` doesn't know what year your model thinks it is. It flags time-sensitive phrasing ("currently", "as of today", "the latest version", "the current X is Y") because those statements decay fastest. False positives are common when the model legitimately has up-to-date information; tune via:

```csharp
opts.Configure<StaleKnowledgeDetector>(c => c.SeverityCap = Severity.Low);
```

## Severity ranges

| Detector | Typical severity | Notes |
|---|---|---|
| `HAL-01` PhantomCitation | High | Fake DOI is a hard signal — no benign explanation |
| `HAL-02` SelfConsistency | Medium | 10× numeric mismatch is suspicious; sometimes legitimate (units, magnitudes) |
| `HAL-03` CrossAgent | High | Multi-agent contradictions undermine workflows |
| `HAL-04` SourceGrounding | Medium | Many false positives when grounding context is sparse |
| `HAL-05` ConfidenceDecay | Low/Medium | Trend-based; rarely Critical |
| `HAL-06` StaleKnowledge | Low | High false-positive rate; route to Log |
| `HAL-07` IntraSessionContradiction | High | Within-conversation contradictions are unambiguous |
| `HAL-08` GroundlessStatistic | Medium | Numeric claims without source are a known LLM failure mode |
| `HAL-09` UncertaintyPropagation | Low | Style signal; helpful in audit but rarely actionable |
