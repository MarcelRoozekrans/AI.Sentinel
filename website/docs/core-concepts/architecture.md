---
sidebar_position: 1
title: Architecture
---

# Architecture

Every call to `GetResponseAsync` or `GetStreamingResponseAsync` runs **two pipeline passes** — one before the LLM, one after.

```
IChatClient.GetResponseAsync(messages)
  │
  ├─ [1] DetectionPipeline.RunAsync(prompt context)
  │       ├─ PromptInjectionDetector
  │       ├─ JailbreakDetector
  │       ├─ ... (many more, parallel)
  │       └─ ThreatRiskScore + detections
  │
  ├─ InterventionEngine.Apply(result)   → Quarantine / Alert / Log / PassThrough
  ├─ AuditStore.AppendAsync(entry)
  │
  ├─ inner IChatClient.GetResponseAsync(messages)
  │
  ├─ [2] DetectionPipeline.RunAsync(response context)
  ├─ InterventionEngine.Apply(result)
  └─ AuditStore.AppendAsync(entry)
```

Detectors run in parallel via `Task.WhenAll`. The aggregate **Threat Risk Score** (0–100) drives the intervention engine, which takes the configured action for the highest severity found.

> Full architecture guide — request lifecycle, severity aggregation, alert deduplication, hash-chained audit — coming soon.
