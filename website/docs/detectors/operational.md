---
sidebar_position: 4
title: Operational detectors
---

# Operational detectors (15)

Operational detectors flag UX and quality issues — repetition loops, truncated output, blank responses, placeholder text, persona drift, sycophancy, language switches. They aren't security threats; they're signals that something is wrong with the model's output that affects user experience or downstream automation.

## Reference

| ID | Detector | Type | Detects |
|---|---|---|---|
| **OPS-01** | `BlankResponseDetector` | Rule-based | Empty or whitespace-only responses |
| **OPS-02** | `RepetitionLoopDetector` | Rule-based | Same sentence repeated 3+ times |
| **OPS-03** | `IncompleteCodeBlockDetector` | Rule-based | Unclosed code fences |
| **OPS-04** | `PlaceholderTextDetector` | Rule-based | `TODO`, `[INSERT HERE]`, `Lorem ipsum` leftovers |
| **OPS-05** | `ContextCollapseDetector` | Semantic | Loss of conversational context across turns |
| **OPS-06** | `AgentProbingDetector` | Semantic | Attempts to map agent capabilities or system prompt |
| **OPS-07** | `QueryIntentDetector` | Semantic | Malicious intent hidden in benign-looking queries |
| **OPS-08** | `ResponseCoherenceDetector` | Semantic | Response that doesn't address the question asked |
| **OPS-09** | `TruncatedOutputDetector` | Rule-based | Mid-sentence truncation and unclosed code fences |
| **OPS-10** | `WaitingForContextDetector` | Semantic | Stall phrases when the user prompt was substantive |
| **OPS-11** | `UnboundedConsumptionDetector` | Rule-based | Compares response length to prompt length; flags unbounded expansion (OWASP LLM04) |
| **OPS-12** | `SemanticRepetitionDetector` | Semantic | Same idea restated with different wording — extends RepetitionLoop beyond literal string matching |
| **OPS-13** | `PersonaDriftDetector` | Semantic | Tone, persona, or stated identity shifts significantly across turns — context poisoning signal |
| **OPS-14** | `SycophancyDetector` | Semantic | Model reverses a stated position purely because the user pushed back — epistemic cowardice |
| **OPS-15** | `WrongLanguageDetector` | Rule-based | Response language doesn't match the user's language (script / charset detection) |

## Severity guidance

Operational issues rarely warrant `Quarantine`. Default routing:

```csharp
opts.OnHigh   = SentinelAction.Alert;   // OPS-01 BlankResponse, OPS-13 PersonaDrift
opts.OnMedium = SentinelAction.Log;     // most OPS-* fire here
opts.OnLow    = SentinelAction.Log;
```

Some operational detectors are noisy by design — they cast a wide net. Disable or clamp the ones that don't fit your domain:

```csharp
// Code-generation app — false positives on incomplete fences during streaming
opts.Configure<IncompleteCodeBlockDetector>(c => c.Enabled = false);

// Multilingual app — wrong-language is expected
opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);

// RAG with long context — semantic repetition is by design
opts.Configure<SemanticRepetitionDetector>(c => c.SeverityCap = Severity.Low);
```

## OPS-09 vs OPS-03 — TruncatedOutput vs IncompleteCodeBlock

`TruncatedOutputDetector` (OPS-09) is the broader signal — it flags any mid-sentence cutoff plus unclosed fences. `IncompleteCodeBlockDetector` (OPS-03) is the narrower fence-only check. If both fire on the same response, that's a hard truncation signal. If only OPS-09 fires, the prose is mid-sentence; if only OPS-03 fires, the prose is fine but a code block is open.

For most apps, leave both enabled and route at `Medium` so audit captures the signal without blocking.

## OPS-11 UnboundedConsumption — DoS prevention

This one *can* warrant `Alert` or `Quarantine`. The detector compares response length to prompt length and flags ratios that look like the model is being prompted to emit unbounded output ("write me 10,000 words about X", followed by 50,000 words of output). This is an OWASP LLM04 signal — token cost amplification.

Tune the threshold by subclassing or routing aggressively:

```csharp
opts.OnHigh = SentinelAction.Quarantine;       // block runaway responses
opts.Configure<UnboundedConsumptionDetector>(c => c.SeverityFloor = Severity.High);
```

## OPS-13 PersonaDrift — context poisoning canary

Persona drift is a low-frequency, high-signal detector. When the model's stated identity, tone, or role shifts across turns of a session, that often means something is poisoning the conversation context — prompt injection from a tool result, retrieval-augmented data, or a user successfully jailbreaking earlier in the conversation. Pair with `SEC-09 IndirectInjection` and `SEC-31 VectorRetrievalPoisoning` for a defense-in-depth view.
