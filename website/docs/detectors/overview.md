---
sidebar_position: 1
title: Overview
---

# Detector overview

AI.Sentinel ships with **55 built-in detectors** across three categories:

| Category | Count | Purpose |
|---|---|---|
| [**Security**](./security) | 31 | Prompt injection, jailbreaks, PII / credential leakage, covert channels, indirect injection, RAG poisoning |
| [**Hallucination**](./hallucination) | 9 | Phantom citations, fabricated authorities, contradictions, stale knowledge, confidence decay |
| [**Operational**](./operational) | 15 | Repetition loops, blank responses, truncated output, language switches, persona drift, sycophancy |

## Detector modes

Every detector falls into one of three execution modes:

- **Rule-based** — fast regex or heuristic. Always active. Sub-microsecond per call.
- **Semantic** — uses embedding cosine similarity via `IEmbeddingGenerator`. Language-agnostic. **No-op until `opts.EmbeddingGenerator` is configured.**
- **LLM escalation** — fires a second-pass LLM classifier. **No-op until `opts.EscalationClient` is configured.** Used for ambiguous or low-confidence rule-based hits.

## Severity model

Each detector returns a `DetectionResult` carrying a `Severity` (`None`, `Low`, `Medium`, `High`, `Critical`) and a reason string. The pipeline aggregates per-detector severities into a [Threat Risk Score](../core-concepts/severity-model) (0–100) that drives the [Intervention Engine](../core-concepts/intervention-engine).

## Detector ID convention

Built-in detectors use three prefixes:

- `SEC-NN` — security
- `HAL-NN` — hallucination
- `OPS-NN` — operational

Custom detectors authored via [`opts.AddDetector<T>()`](../custom-detectors/sdk-overview) **must** use a different prefix to avoid collisions with future official detectors. Examples: `ACME-01`, `MYORG-CUSTOM-01`.

## Tuning

Every detector — built-in or custom — can be disabled or have its severity output clamped via [`opts.Configure<T>(c => ...)`](../configuration/fluent-config). Floor and Cap apply only to firing results; Clean results pass through unchanged.

```csharp
opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);
opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);
```

## Where to next

- [Security detectors](./security) — 31 detectors
- [Hallucination detectors](./hallucination) — 9 detectors
- [Operational detectors](./operational) — 15 detectors
- [Writing a custom detector](../custom-detectors/writing-a-detector) — IDetector contract + the SDK
