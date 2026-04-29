---
sidebar_position: 2
title: Detection pipeline
---

# Detection pipeline

`IDetectionPipeline` is the parallel fan-out runner that invokes every registered `IDetector` against a `SentinelContext`. The default implementation `DetectionPipeline` is what `services.AddAISentinel()` wires up.

## Lifecycle

```csharp
public interface IDetectionPipeline
{
    ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct);
}
```

The pipeline is invoked **once per pass** — twice per `IChatClient.GetResponseAsync` call (prompt + response). It's a singleton, owned by DI; you don't instantiate it directly.

## Internal flow

```
1. Filter — skip detectors disabled via Configure<T>(c => c.Enabled = false)
2. Dispatch — invoke every remaining detector's AnalyzeAsync(ctx, ct) in parallel
3. Fast path — if all ValueTasks completed synchronously, harvest results directly
4. Slow path — otherwise Task.WhenAll over the AsTask() projections
5. Clamp — apply Configure<T>(c => c.SeverityFloor / c.SeverityCap) to firing results
6. Escalate — for ILlmEscalatingDetector hits at Medium+, run the LLM classifier
7. Aggregate — sum into ThreatRiskScore, return PipelineResult
```

## Filter — skip-on-disabled

`Configure<T>(c => c.Enabled = false)` is applied at construction time. Disabled detectors **never enter** the `_detectors` array — zero CPU cost. There's no per-call branch checking enabled-ness.

```csharp
opts.Configure<RepetitionLoopDetector>(c => c.Enabled = false);
// RepetitionLoopDetector is filtered out of the pipeline at startup.
// It's never invoked, never times-out, never allocates per call.
```

This filtering happens once, when DI builds `DetectionPipeline`. Toggling `Enabled` after the pipeline is built has no effect — it's a startup-time choice.

## Dispatch — parallel fan-out

```csharp
// Pseudocode of the actual implementation
var vTasks = ArrayPool<ValueTask<DetectionResult>>.Shared.Rent(_detectors.Length);
for (int i = 0; i < _detectors.Length; i++)
    vTasks[i] = _detectors[i].AnalyzeAsync(ctx, ct);
```

Each detector's `AnalyzeAsync` is a `ValueTask<DetectionResult>` — synchronous return for rule-based detectors that complete without IO, async return for semantic detectors that hit `IEmbeddingGenerator` and LLM-escalation detectors that do `IChatClient` round-trips.

## Fast path / slow path

If every detector completed synchronously (typical for rule-based-only deployments), the pipeline harvests results directly without `Task.WhenAll` ceremony. This is the common case for the default 25 rule-based detectors when no embedding generator is configured.

If any detector returned an incomplete `ValueTask`, the pipeline projects to `Task[]` and `await Task.WhenAll(tasks)` — the slow path. Used whenever semantic or escalation detectors are active.

## Clamp pass — Floor / Cap

Between dispatch and escalation, the pipeline applies per-detector severity clamps from `Configure<T>(c => c.SeverityFloor = ...)` / `c.SeverityCap = ...`:

- **Floor**: if a firing detector emits below `Floor`, rewrite to `Floor`. (Clean results unaffected.)
- **Cap**: if a firing detector emits above `Cap`, rewrite to `Cap`. (Clean results unaffected.)

The rewrite uses `result with { Severity = clamped }` (record `with`-expression) so `DetectorId` and `Reason` are preserved verbatim.

```csharp
opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
// JailbreakDetector emits Low → pipeline rewrites to High.
// The audit entry will say Severity.High but Reason="…the original raw reason"
```

See the [`Configure<T>` page](../configuration/fluent-config) for tuning patterns and the audit-observability follow-up backlog item.

## Escalation — LLM classifier

Some detectors (`SEC-08 EntropyCovertChannel`, future stub detectors) flag content as *suspicious* but don't have enough signal to be confident. They implement `ILlmEscalatingDetector` instead of `IDetector`.

When such a detector emits `Severity.Medium` or higher, the pipeline runs a second-pass LLM classifier:

```csharp
// What the pipeline does internally for ILlmEscalatingDetector hits:
var instruction = new ChatMessage(ChatRole.System, $$"""
    You are a security classifier. A rule-based detector (rule ID: {{detector.Id}})
    flagged incoming content at severity {{initial.Severity}}.
    Your task: assess whether the content justifies {{initial.Severity}} severity or should be lower.
    Respond with JSON only: {"severity":"None|Low|Medium|High|Critical","reason":"one sentence"}
    """);
var response = await escalationClient.GetResponseAsync(new[] { instruction, contentMessage });
// Parse the JSON, override the detector's emitted severity if the LLM downgrades or upgrades.
```

Escalation requires `opts.EscalationClient` — without it, `ILlmEscalatingDetector` hits pass through unchanged. Escalation runs sequentially for each escalating hit (rare path, low-frequency by design).

## Aggregation — `PipelineResult`

```csharp
public sealed record PipelineResult(
    ThreatRiskScore Score,                     // 0–100, aggregate of all detector severities
    IReadOnlyList<DetectionResult> Detections);  // every firing detection (Clean ones omitted)
```

`Score` is computed from individual severity scores — see [Severity model](./severity-model) for the formula. `Detections` excludes Clean results; only firing detectors appear.

## What runs in parallel, what doesn't

| Stage | Concurrency |
|---|---|
| Detector dispatch | Parallel — all detectors fire simultaneously |
| Embedding cache lookups | Parallel — `IEmbeddingCache.TryGet` is in-process, no contention |
| `IEmbeddingGenerator.GenerateAsync` | Per-detector, but if multiple semantic detectors call it on the same call the underlying generator decides batching. Cache hits skip the call entirely. |
| LLM escalation | Sequential — one escalating hit at a time, after dispatch completes |
| Intervention engine | After pipeline returns — sequential, one action per call |
| Audit append | After intervention — sequential per call, but audit forwarders fan out async |

Per call, the wall-clock time is dominated by the slowest semantic detector (or the LLM escalation, if any). Rule-based detectors are essentially free.

## Per-pipeline configuration

In a multi-pipeline setup ([named pipelines](../configuration/named-pipelines)), each pipeline has its own `DetectionPipeline` instance with its own filter set, its own clamp configuration, and its own escalation client. Detector instances are shared (singletons in DI), but their effective configuration is per-pipeline.

## Next: [Intervention engine](./intervention-engine)
