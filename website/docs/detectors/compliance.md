---
sidebar_position: 5
title: Compliance detectors
---

# Compliance detectors (4)

Compliance detectors flag requests to use the model for a practice that Art. 5 of the EU AI Act ([Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)) prohibits. They look for the *attempt*: a user asking the assistant to build a social score, read employees' emotions or guess someone's religion from a photo. They do not decide whether your system is a prohibited AI practice, and using them does not make a system compliant.

## Reference

| ID | Detector | Type | Detects |
|---|---|---|---|
| **CMP-01** | `SocialScoringDetector` | Semantic ⚠️ | Rating or classifying people by social behaviour or personal traits in a way that leads to worse treatment (Art. 5(1)(c)) |
| **CMP-02** | `WorkplaceEmotionRecognitionDetector` | Semantic ⚠️ | Inferring the emotions of employees or students from their face, voice or other biometric data (Art. 5(1)(f)) |
| **CMP-03** | `SensitiveBiometricCategorisationDetector` | Semantic ⚠️ | Deducing race, religion, political views, trade union membership or sexual orientation from photos, voice or other biometric data (Art. 5(1)(g)) |
| **CMP-04** | `ProfilingCrimePredictionDetector` | Semantic ⚠️ | Predicting that a person will commit a crime from profiling or personality traits alone (Art. 5(1)(d)) |

Not covered: subliminal or manipulative techniques, exploiting vulnerabilities, untargeted scraping of facial images, and real-time remote biometric identification. Those depend on how a system is built and deployed, not on what a user types, so a content detector cannot see them.

## Off by default

The four detectors do not run unless you enable them. They are semantic and their thresholds depend on the embedding model, so they are an informed opt-in, not a default.

```csharp
services.AddAISentinel(opts =>
{
    opts.EnableComplianceDetectors();                                        // all four
    // or one at a time:
    opts.Configure<SensitiveBiometricCategorisationDetector>(c => c.Enabled = true);
});
```

In the CLIs, set `SENTINEL_HOOK_COMPLIANCE=on` for `sentinel-hook` and `sentinel-copilot-hook`, and `SENTINEL_MCP_COMPLIANCE=on` for `sentinel-mcp`. The MCP proxy falls back to `SENTINEL_HOOK_COMPLIANCE` when its own variable is unset. The CLIs take no threshold settings; they use the built-in thresholds.

## They need an embedding generator

All four are semantic: each compares the message with example phrases by embedding similarity. With no `opts.EmbeddingGenerator` they return `Clean` on every scan, and AI.Sentinel warns at startup that semantic detection is off.

```csharp
services.AddAISentinel(opts =>
{
    opts.EmbeddingGenerator = embeddingGenerator; // any IEmbeddingGenerator<string, Embedding<float>>
});
```

The CLIs and the MCP proxy take `SENTINEL_EMBEDDING_ENDPOINT` and `SENTINEL_EMBEDDING_MODEL`.

## Thresholds are tuned on all-MiniLM-L6-v2

The built-in thresholds were set from an [evaluation against a real embedding model](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/superpowers/evaluations/2026-10-17-compliance-detectors.md), `sentence-transformers/all-MiniLM-L6-v2`. Each High threshold sits above every legitimate request in the evaluation set, including the exemptions Art. 5 itself makes, at the cost of recall:

| ID | High | Medium |
|---|---|---|
| CMP-01 | 0.44 | 0.39 |
| CMP-02 | 0.58 | 0.48 |
| CMP-03 | 0.65 | 0.55 |
| CMP-04 | 0.47 | 0.46 |

On that model, no legitimate request reached High or Medium, and 5 of 13 paraphrased prohibited requests reached High, 4 more reached Medium and 4 were missed. CMP-03 is the weakest: a legitimate face-dataset bias audit scores closer to its examples than its positives do, so it reports Medium at most on the evaluated phrases.

The thresholds are model-dependent. Other models use a different similarity scale: on `BAAI/bge-base-en-v1.5`, the same thresholds put more than half of the legitimate requests' scores at High. With another embedding model, set the thresholds for that model:

```csharp
opts.Configure<SocialScoringDetector>(c =>
{
    c.Enabled = true;
    c.HighThreshold = 0.70f;
    c.MediumThreshold = 0.65f;
});
```

Both must be in (0, 1], and Medium must not exceed High. `AddAISentinel` rejects a pair that breaks this, and building the pipeline rejects an override that crosses the other, built-in value, so when you raise or lower one, set both. Each named pipeline can set its own.

### Find the thresholds for your model

`tools/AI.Sentinel.ComplianceEval` in the repository scores the evaluation phrases against the four detectors with a local ONNX model, and prints the thresholds its rule gives for that model in the last column of the summary:

```bash
git clone https://github.com/MarcelRoozekrans/AI.Sentinel
cd AI.Sentinel
dotnet run --project tools/AI.Sentinel.ComplianceEval -- --model bge-base-en-v1.5 --out results.md
```

`--model` is `all-MiniLM-L6-v2` (default) or `bge-base-en-v1.5`; the model is downloaded to `~/.cache/ai-sentinel/models/` on first run. For another model, add it to `EmbeddingModel.Known` in the tool, or replace `OnnxSentenceEmbeddingGenerator` with the `IEmbeddingGenerator` your application uses. The rule sets High 0.05 and Medium 0.02 above the closest legitimate request, so that no near-miss in the set is reported. The tool exits 1 when a legitimate request reaches High with the thresholds the detectors currently use.

## Default action: Alert

A strong match is `High`, and a stock `AddAISentinel()` install maps `High` to `Alert`: the detection is written to the audit log, sent to any configured alert sink and shown on the dashboard, and the call goes through. A weaker match is `Medium`, which maps to `Log`: it is written to the audit log only. To block instead, raise one detector's action:

```csharp
opts.Configure<SensitiveBiometricCategorisationDetector>(c => c.Action = SentinelAction.Quarantine);
```

The hook CLIs and the MCP proxy map other detectors' `High` findings through `SENTINEL_HOOK_ON_HIGH`, which defaults to `Block`. They give these four detectors the `Alert` action instead, so a compliance finding is audited and surfaced as a warning: `sentinel-hook` and `sentinel-copilot-hook` exit 0 with the reason on stderr, and the MCP proxy forwards the call. In the hook CLIs, mapping the finding's severity to `Allow` still suppresses the warning; the audit entry is written either way.

## Both legs

The detectors scan the request and the reply. A reply that quotes the user's request, for example in a refusal, fires on its own leg too, so one exchange can produce two audit entries for the same detector, one per leg. The audit entry records the detector id, severity and a fixed reason; it never contains the message.

## Expect false positives near these topics

Embedding similarity measures how close a message is to the examples, not what the user intends. Legitimate requests on nearby topics can score high:

- an optional, anonymous wellbeing survey;
- aggregate, anonymous sentiment over customer or staff feedback;
- accessibility features such as describing an image for a blind user;
- a clinician discussing a patient's mood;
- a credit check on financial data;
- a performance review based on work output;
- research on recidivism statistics.

Because the default action is `Alert`, a false positive costs a review, not a blocked user. Review the Compliance chip on the [dashboard](../getting-started/dashboard) before you raise any of these to `Quarantine`, and enable only the detectors that fit your domain: `EnableComplianceDetectors()` turns on all four, `Configure<T>(c => c.Enabled = true)` one.
