---
sidebar_position: 1
title: Overview
---

# Detector overview

AI.Sentinel ships with **60 built-in detectors** across four categories:

| Category | Count | Purpose |
|---|---|---|
| [**Security**](./security) | 32 | Prompt injection, jailbreaks, PII / credential leakage, covert channels, indirect injection, RAG poisoning |
| [**Hallucination**](./hallucination) | 9 | Phantom citations, fabricated authorities, contradictions, stale knowledge, confidence decay |
| [**Operational**](./operational) | 15 | Repetition loops, blank responses, truncated output, language switches, persona drift, sycophancy |
| [**Compliance**](./compliance) | 4 | Requests for practices the EU AI Act prohibits in Art. 5: social scoring, emotion recognition at work or school, sensitive biometric categorisation, crime prediction from profiling. **Off by default**; enable with `opts.EnableComplianceDetectors()` |

The 56 Security, Hallucination and Operational detectors run by default; the 4 Compliance detectors are opt-in.

## Detector modes

Every detector falls into one of these execution modes:

- **Rule-based** — fast regex or heuristic. Always active. Sub-microsecond per call.
- **Semantic ⚠️** — uses embedding cosine similarity via `IEmbeddingGenerator`. Language-agnostic. **Returns `Clean` on every scan until `opts.EmbeddingGenerator` is configured.** The ⚠️ marks a detector inactive in a default install. The CLIs and MCP proxy enable it with `SENTINEL_EMBEDDING_ENDPOINT` and `SENTINEL_EMBEDDING_MODEL`.
- **LLM escalation** — not a detector type but a second pass: when `opts.EscalationClient` is set, a finding already at `Medium` or above is re-classified by an LLM. It upgrades or downgrades an existing finding; it cannot create one.
- **Rule + Semantic ⚠️** — a high-precision rule layer runs first and always, so the unambiguous phrasings are caught with no generator; anything needing context falls through to the semantic path.
- **Stub** — a placeholder with no implementation; always returns `Clean`. Setting `opts.EscalationClient` does **not** activate it, because escalation only re-classifies findings a detector has already produced.

## How semantic detectors score

A semantic detector embeds the text of each message that is new in the scan, compares it by cosine similarity with its High, Medium and Low reference examples, and reports the most severe bucket any message reaches. A message's text is its text plus the results of the tool calls it carries. Redaction placeholders such as `[EMAIL_1_k3f9x2]` are normalised to `[EMAIL]` first.

**Changed in 3.1: each new message is scored on its own.** Semantic detectors used to embed the whole conversation as one text. They now embed each message that is new in the scan, at most the newest 16, and the most severe match decides.

- In long conversations the semantic detectors find more, because a short malicious message is no longer diluted by the rest of the chat.
- A finding no longer repeats on every later turn. On the prompt path only the current turn is judged: the messages after the last assistant message. A client that resends history without assistant messages still has every message judged.
- The system prompt from `ChatOptions.Instructions` is scored only on a conversation's first turn, when there is no assistant message yet.
- Tool results carried as `FunctionResultContent` are scored: a string as it is, a `JsonElement` as its raw text, anything else as compact JSON. A result that cannot be serialised is skipped, and the rest of the scan is still scored.
- The public `ScanMessagesAsync` now judges each message of its list separately instead of joining them.
- Each semantic detector makes one embedding call per scan for the new messages it has not seen; history and repeated tool results hit the embedding cache, and redaction placeholders no longer defeat it.
- Tuning: CMP-01 moves to High 0.50 and Medium 0.42, from 0.44 and 0.39; CMP-02 to Medium 0.56, from 0.48, with High unchanged at 0.58; CMP-03 to High 0.66, from 0.65, with Medium unchanged at 0.55. CMP-04 is unchanged. At the 3.0 values, legitimate requests the thresholds had not been fitted to fired: a fairness report on a photo-tagging model reached High on CMP-01, and a demographics dashboard and an interview transcription request reached Medium, so the compliance detectors are stricter and catch fewer of the evaluated prohibited requests: 7 of 17 at High or Medium on all-MiniLM-L6-v2, down from 9. CMP-03 recall is not improved, at 1 of 7; see [#433](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/433) and the [compliance detectors](./compliance) page.
- `SemanticDetectorBase.GetText` is obsolete, warning `SENTINEL001`; override `GetTextsToScore`. An existing `GetText` override is still scored.

The semantic layers of SEC-01, SEC-05 and SEC-09 miss paraphrased injections on local embedding models; that is tracked in [#432](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/432).

## Severity model

Each detector returns a `DetectionResult` carrying a `Severity` (`None`, `Low`, `Medium`, `High`, `Critical`) and a reason string. The pipeline aggregates per-detector severities into a [Threat Risk Score](../core-concepts/severity-model) (0–100) that drives the [Intervention Engine](../core-concepts/intervention-engine).

## Detector ID convention

Built-in detectors use four prefixes:

- `SEC-NN` — security
- `HAL-NN` — hallucination
- `OPS-NN` — operational
- `CMP-NN` — compliance

Custom detectors authored via [`opts.AddDetector<T>()`](../custom-detectors/sdk-overview) **must** use a different prefix to avoid collisions with future official detectors. Examples: `ACME-01`, `MYORG-CUSTOM-01`.

## Tuning

Every detector — built-in or custom — can be disabled or have its severity output clamped via [`opts.Configure<T>(c => ...)`](../configuration/fluent-config). Floor and Cap apply only to firing results; Clean results pass through unchanged.

```csharp
opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);
opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);
```

## Where to next

- [Security detectors](./security) — 32 detectors
- [Hallucination detectors](./hallucination) — 9 detectors
- [Operational detectors](./operational) — 15 detectors
- [Compliance detectors](./compliance) — 4 detectors
- [Writing a custom detector](../custom-detectors/writing-a-detector) — IDetector contract + the SDK
