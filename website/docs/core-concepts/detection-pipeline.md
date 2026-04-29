---
sidebar_position: 2
title: Detection pipeline
---

# Detection pipeline

`IDetectionPipeline` is the parallel-fan-out runner that invokes every registered `IDetector` against a `SentinelContext`. Detectors emit `DetectionResult` records that aggregate into a `PipelineResult` carrying the highest severity, all firing detections, and a `ThreatRiskScore` (0–100).

The pipeline supports per-detector configuration via `opts.Configure<T>(c => ...)` — disable, clamp severity floor/cap — applied between detector dispatch and LLM escalation.

> Full detection pipeline guide — detector modes (rule-based / semantic / LLM-escalation), parallel-task pooling, escalation prompt format — coming soon.
