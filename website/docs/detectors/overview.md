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

Every detector falls into one of three execution modes, and a fourth label marks placeholders:

- **Rule-based** — fast regex or heuristic. Always active. Sub-microsecond per call.
- **Semantic ⚠️** — uses embedding cosine similarity via `IEmbeddingGenerator`. Language-agnostic. **Returns `Clean` on every scan until `opts.EmbeddingGenerator` is configured.** The ⚠️ marks a detector inactive in a default install. The CLIs and MCP proxy enable it with `SENTINEL_EMBEDDING_ENDPOINT` and `SENTINEL_EMBEDDING_MODEL`.
- **LLM escalation** — not a detector type but a second pass: when `opts.EscalationClient` is set, a finding already at `Medium` or above is re-classified by an LLM. It upgrades or downgrades an existing finding; it cannot create one.
- **Stub** — a placeholder with no implementation; always returns `Clean`. Setting `opts.EscalationClient` does **not** activate it, because escalation only re-classifies findings a detector has already produced.

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
