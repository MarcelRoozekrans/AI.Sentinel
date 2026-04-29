---
sidebar_position: 5
title: Severity model
---

# Severity model

AI.Sentinel uses a five-level severity scale and aggregates per-detector severities into a numeric **Threat Risk Score** (0–100) that drives intervention decisions and dashboard visualization.

## The `Severity` enum

```csharp
public enum Severity
{
    None = 0,    // detector ran, no threat — DetectionResult.IsClean == true
    Low,
    Medium,
    High,
    Critical,
}
```

| Severity   | Use when                                                                |
|------------|-------------------------------------------------------------------------|
| `Critical` | Active exploitation, data exfiltration, credential leak                 |
| `High`     | Likely threat with high confidence (e.g., direct injection phrase match)|
| `Medium`   | Suspicious pattern with moderate confidence                             |
| `Low`      | Anomaly worth flagging but probably benign                              |
| `None`     | No threat — `DetectionResult.IsClean == true`                           |

## Threat Risk Score (0–100)

Each detector emits a severity. The pipeline computes a per-detector score and aggregates:

| Severity | Per-detector score |
|---|---|
| `Critical` | 100 |
| `High` | 70 |
| `Medium` | 40 |
| `Low` | 15 |
| `None` | 0 |

The aggregate is **not the simple sum** — it's a saturating max-with-decay so a single Critical doesn't compound with multiple Mediums into noise. Conceptually:

```
Score = max-with-attenuation over firing detectors
```

Cap at 100. Round to int. The dashboard's gauge maps the 0–100 score to four bands:

| Band | Range | UI color |
|---|---|---|
| **SAFE** | 0–14 | green |
| **WATCH** | 15–39 | yellow |
| **ALERT** | 40–69 | orange |
| **ISOLATE** | 70–100 | red |

## How severity flows

```
[1] Detector emits DetectionResult { Severity = Low, ... }
     │
[2] Configure<T>(c => c.SeverityFloor = High) clamps Low → High
     │
[3] LLM escalation may further adjust (Medium → Critical, etc.)
     │
[4] Engine reads MaxSeverity from PipelineResult.Detections
     │
[5] Engine maps severity → SentinelAction via opts.OnXxx properties
     │
[6] AuditEntry records the post-clamp severity
```

The clamp pass means audit entries reflect **policy-applied** severity, not raw detector output. If you need both, use the [`DetectionResult` clamp annotation](https://github.com/ZeroAlloc-Net/AI.Sentinel/blob/main/docs/BACKLOG.md) (backlog) or compute pre-clamp from the detector source.

## Where each detector falls

Every detector has a typical severity range. Some pin to a single level (`SEC-23 PiiLeakage` emits `Critical` for credit cards, `Medium` for phone numbers — it's pattern-class-driven). Others span the whole range based on their semantic-similarity bucket (any `SemanticDetectorBase` subclass: `High` if a high-bucket example matches at >0.90 cosine, `Medium` at >0.82, `Low` at >0.75, otherwise `Clean`).

| Detector type | Severity behavior |
|---|---|
| Rule-based, single pattern class | One severity per detector |
| Rule-based, multi-pattern (e.g., PII) | Pattern-driven; different patterns emit different severities |
| Semantic (`SemanticDetectorBase`) | Bucket-driven: `HighThreshold` (default 0.90) → High, `MediumThreshold` (0.82) → Medium, `LowThreshold` (0.75) → Low |
| LLM escalation | Initial rule-based hit, then LLM may downgrade or upgrade |

See the [detector reference pages](../detectors/overview) for per-detector severity guidance.

## Action mapping

```csharp
opts.OnCritical = SentinelAction.Quarantine;
opts.OnHigh     = SentinelAction.Alert;
opts.OnMedium   = SentinelAction.Log;
opts.OnLow      = SentinelAction.Log;
```

The intervention engine looks up the action for the **maximum severity** across firing detectors. If three detectors fire (Low, Medium, High) on a single call, the engine applies `OnHigh = Alert`. The other detections still appear in audit, but only the max-severity action is taken.

## Tuning per detector

`Configure<T>(c => c.SeverityFloor / c.SeverityCap)` lets you reshape a detector's severity output without changing detector code:

```csharp
// JailbreakDetector might emit Low for borderline matches — promote to High so it triggers Alert/Quarantine
opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);

// RepetitionLoopDetector is noisy on legitimate code-generation responses — clamp to Low so it just logs
opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);

// WrongLanguageDetector is irrelevant in a multilingual app — disable entirely
opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);
```

Floor and Cap apply only to **firing** results — Clean results pass through unchanged. You can't fabricate a detection by setting `Floor = High` on a non-firing detector.

See the [`Configure<T>` page](../configuration/fluent-config) for the full rules and examples.

## Severity in the API

| Surface | What you see |
|---|---|
| `DetectionResult.Severity` | What the detector emitted (post-clamp) |
| `PipelineResult.MaxSeverity` | Highest severity among firing detectors |
| `PipelineResult.Score` | Aggregate ThreatRiskScore (0–100) |
| `AuditEntry.Severity` | What the entry records — same as `DetectionResult.Severity` |
| `SentinelException.PipelineResult.MaxSeverity` | Quarantine action carries this |
| Dashboard gauge | Maps `Score` to SAFE/WATCH/ALERT/ISOLATE bands |

## Defaults

If you don't configure `OnCritical`/`OnHigh`/`OnMedium`/`OnLow` at all, every action is `Log`. That's the conservative default — the framework won't break your app the moment you wire it up; you opt into stricter actions explicitly.

A reasonable production starting point:

```csharp
opts.OnCritical = SentinelAction.Quarantine;
opts.OnHigh     = SentinelAction.Alert;
opts.OnMedium   = SentinelAction.Log;
opts.OnLow      = SentinelAction.Log;
```

Tune from there as you learn which detectors fire frequently in your domain — disable the noisy ones, clamp the borderline ones, and let the high-confidence threats reach the action tier they deserve.
