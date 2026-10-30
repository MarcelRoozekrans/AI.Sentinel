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

### Replaying with `sentinel scan`

`sentinel scan` in the [`AI.Sentinel.Cli`](https://www.nuget.org/packages/AI.Sentinel.Cli) tool replays a saved conversation through the detector pipeline. It leaves the four detectors off too, so `--expect CMP-03` fails unless the scan runs them. Pass `--compliance`, or set `SENTINEL_HOOK_COMPLIANCE=on`, the same switch the hook CLIs use, so a scan reproduces their findings:

```
sentinel scan conversation.json --compliance --expect CMP-03
```

Like the hooks, the scan needs `SENTINEL_EMBEDDING_ENDPOINT` and `SENTINEL_EMBEDDING_MODEL` for these detectors to fire.

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

The built-in thresholds were set from an [evaluation against a real embedding model](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/superpowers/evaluations/2026-10-17-compliance-detectors.md), `sentence-transformers/all-MiniLM-L6-v2`. Each High threshold sits above every legitimate request in the evaluation's tuning set, including the exemptions Art. 5 itself makes, at the cost of recall. Since 4.2 each detector also has its own `ReviewThreshold`: a text that reaches neither bucket still goes to the [second-stage reviewer](./overview#second-stage-review) from that similarity up, when one is configured.

| ID | High | Medium | `ReviewThreshold` |
|---|---|---|---|
| CMP-01 | 0.55 | 0.42 | 0.41 |
| CMP-02 | 0.58 | 0.56 | 0.42 |
| CMP-03 | 0.53 | 0.44 | 0.40 |
| CMP-04 | 0.48 | 0.40 | 0.31 |

In 3.1 the evaluation set grew to 52 legitimate requests, 13 of them written and committed before they were scored. Scored against the 3.0 thresholds, those unseen requests fired: a request for a fairness report on a photo-tagging model reached High on CMP-01. The 3.1 thresholds are therefore set over the larger set, which raised CMP-01's High and Medium, CMP-02's Medium and CMP-03's High.

In 3.1, on that model, 4 of 17 paraphrased prohibited requests reached High, 3 more reached Medium and 10 were missed. CMP-03 was the weakest. A legitimate test of an image classifier's accuracy across ethnic groups scored above 6 of its 7 positives, so CMP-03 reported 1 of 7, at Medium.

**Changed in 4.2: held-out results, and a review band for each detector ([#433](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/433)).** The evaluation set grew to 50 prohibited requests and 94 legitimate ones. 11 prohibited and 14 legitimate requests are held out: written and committed before they were scored, and never used for tuning. CMP-03 and CMP-04 have new examples, and every value above is tuned on all-MiniLM-L6-v2.

- **Recall, held-out.** Embeddings alone flag, at `Medium` or above, 0 of 2, 1 of 2, 2 of 5 and 0 of 2 on CMP-01 to CMP-04. With the 3.1 values the same requests gave 0, 1, 2 and 1. With an LLM judge as reviewer, 1, 1, 4 and 1 are caught. CMP-01 and CMP-03 gain through the reviewer. CMP-04 loses its one embedding-only catch, 1 to 0, because the pickpocketing request scored 0.507 at `High` with the 3.1 values and scores 0.315 now; a judge recovers it, and the 3.1 `High` false positive is gone. The held-out set is small: with 2 held-out positives, one request moves CMP-01's, CMP-02's or CMP-04's recall by 50 points.
- **Review latency in the hooks.** `sentinel-hook` and `sentinel-copilot-hook` give a review 3 s by default. In one run, 3 of the 14 compliance reviews took longer than that, all on prohibited requests, and a hook would have abandoned them. Raise `SENTINEL_REVIEW_TIMEOUT_MS` if you rely on the judge for recall; [#537](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/537) tracks the hooks' timeout.
- **False positives, held-out.** No legitimate request reaches High. Two reach CMP-04's Medium bucket: a police training module on why judging criminality by appearance discriminates, and police sorting victim images from a court-ordered copy of a suspect's storage. The judge cleared both, and every other legitimate candidate. With the 3.1 values the training module reached High.
- **Known misses.** 5 tuning requests and 4 held-out requests score below `ReviewThreshold`, so a reviewer does not see them either. Among them are religion inferred from voicemails or fingerprints and politics from handwriting or livestream footage.
- **An earlier held-out batch failed.** A summary of the research on why sexual-orientation detection from faces is unsound reached CMP-03's High at 0.618. That batch was folded into the tuning set, and the results above come from a fresh one.

The thresholds are model-dependent. Other models use a different similarity scale: on `BAAI/bge-base-en-v1.5`, the same thresholds put more than half of the legitimate requests' scores at High. With another embedding model, set the thresholds for that model:

```csharp
opts.Configure<SocialScoringDetector>(c =>
{
    c.Enabled = true;
    c.HighThreshold = 0.70f;
    c.MediumThreshold = 0.65f;
});
```

Both must be in (0, 1], and Medium must not exceed High. A configured `ReviewThreshold` must not exceed the Medium threshold. `AddAISentinel` rejects a pair that breaks this, and building the pipeline rejects an override that crosses the other, built-in value, so when you raise or lower one, set both. Each named pipeline can set its own.

### Find the thresholds for your model

`tools/AI.Sentinel.ComplianceEval` in the repository scores the evaluation phrases against the four detectors with a local ONNX model, and prints the thresholds its rule gives for that model in the summary. It also prints the lowest tuning positive's similarity to any example set: the highest `ReviewThreshold` at which every tuning positive reaches the reviewer. Run it with `--tuning`, so it scores only the tuning phrases and the held-out ones stay unseen:

```bash
git clone https://github.com/MarcelRoozekrans/AI.Sentinel
cd AI.Sentinel
dotnet run --project tools/AI.Sentinel.ComplianceEval -- --model bge-base-en-v1.5 --tuning --out results.md
```

`--model` is `all-MiniLM-L6-v2` (default) or `bge-base-en-v1.5`; the model is downloaded on first run to `~/.cache/ai-sentinel/models/`, from a pinned Hugging Face commit whose SHA-256 the tool checks. For another model, add it to `EmbeddingModel.Known` in the tool, or replace `OnnxSentenceEmbeddingGenerator` with the `IEmbeddingGenerator` your application uses. The rule sets High 0.05 and Medium 0.02 above the closest legitimate request, so that no near-miss in the set is reported. The tool exits 1 when a legitimate request reaches High with the thresholds the detectors currently use.

## Default action: Alert

A strong match is `High` only with a reviewer that confirms it, or with `CapSemanticSeverity = false`, and is otherwise capped at `Medium`. A stock `AddAISentinel()` install maps `High` to `Alert`: the detection is written to the audit log, sent to any configured alert sink and shown on the dashboard, and the call goes through. A weaker match is `Medium`, which maps to `Log`: it is written to the audit log only. To block instead, raise one detector's action:

```csharp
opts.Configure<SensitiveBiometricCategorisationDetector>(c => c.Action = SentinelAction.Quarantine);
```

The hook CLIs and the MCP proxy map other detectors' `High` findings through `SENTINEL_HOOK_ON_HIGH`, which defaults to `Block`. They give these four detectors the `Alert` action instead, at `Medium` as well as `High`, so a compliance finding of either severity is audited and surfaced as a warning: `sentinel-hook` exits 0 with the reason in a `systemMessage`, `sentinel-copilot-hook` exits 0 with the reason on stderr, and the MCP proxy forwards the call. In the hook CLIs, mapping the finding's severity to `Allow` still suppresses the warning; the audit entry is written either way.

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
- research on recidivism statistics;
- an explanation or critique of the prohibited practice itself, such as a training module or a literature review on why such systems discriminate or do not work.

Because the default action is `Alert`, a false positive costs a review, not a blocked user. Review the Compliance chip on the [dashboard](../getting-started/dashboard) before you raise any of these to `Quarantine`, and enable only the detectors that fit your domain: `EnableComplianceDetectors()` turns on all four, `Configure<T>(c => c.Enabled = true)` one.
