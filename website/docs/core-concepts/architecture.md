---
sidebar_position: 1
title: Architecture
---

# Architecture

AI.Sentinel sits between your application and the LLM. Every call to `IChatClient.GetResponseAsync` (or `GetStreamingResponseAsync`) runs **two pipeline passes** — one before the request reaches the LLM, one after the response comes back. Both passes go through the same `IDetectionPipeline`, the same `InterventionEngine`, and the same `IAuditStore`.

```
IChatClient.GetResponseAsync(messages)
  │
  ├─ [1] DetectionPipeline.RunAsync(prompt context)
  │       ├─ PromptInjectionDetector
  │       ├─ JailbreakDetector
  │       ├─ ... (53 more, parallel)
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

If pass 1 quarantines, pass 2 never runs — the inner LLM call is skipped. This is the design intent: stop bad inputs at the front door so token budget isn't burned on attack traffic.

## Components

| Component | Lifetime | Purpose |
|---|---|---|
| **`SentinelChatClient`** | per-resolution | The middleware wrapper installed by `.UseAISentinel()`. Drives both pipeline passes and threads `SentinelContext` through. |
| **`IDetectionPipeline`** | singleton | Fan-out runner that invokes every registered `IDetector` in parallel against a `SentinelContext`. |
| **`IDetector`** | singleton (per type) | Stateless analyzer. Returns `DetectionResult { Severity, DetectorId, Reason }`. Three modes: rule-based, semantic, LLM-escalation. |
| **`InterventionEngine`** | singleton | Maps the highest fired severity to a `SentinelAction` and applies it. |
| **`IAuditStore`** | singleton | Append-only record of every detection. Default `RingBufferAuditStore`; persistent `SqliteAuditStore` opt-in. |
| **`IAlertSink`** | singleton | Where `Alert` actions go. Default `NullAlertSink`; `WebhookAlertSink` for HTTP push. |
| **`IAuditForwarder[]`** | singletons | Fan-out destinations for audit entries — NDJSON, Azure Sentinel, OpenTelemetry, custom. |
| **`IToolCallGuard`** | singleton | Authorization layer for tool calls. Evaluates `IAuthorizationPolicy` instances against `ISecurityContext`. Separate from detection pipeline. |

## SentinelContext

Every pass gets a `SentinelContext` carrying:

- **`SenderId` / `ReceiverId`** — `AgentId` value objects. Defaults: `"user"` → `"assistant"`.
- **`SessionId`** — stable across the two passes of a single chat call.
- **`Messages`** — the prompt or response messages being scanned.
- **`History`** — previous `AuditEntry` records from the same session, available to detectors that span turns (`HAL-07 IntraSessionContradiction`, `OPS-13 PersonaDrift`, etc.).
- **`LlmId`** — optional model identifier passed via `ChatOptions.ModelId`.

Detectors read from this context and emit `DetectionResult`s.

## Two passes, one context

Pass 1 (prompt scan) sees:
- The user's incoming `Messages`
- The session's `History`
- Whatever the host added (system prompt, tool messages, retrieved documents)

Pass 2 (response scan) sees:
- The LLM's response message(s) appended to `Messages`
- The same `History` (audit entries from pass 1 are added before pass 2)
- The same `SessionId`, `SenderId` (now reversed — `"assistant"` → `"user"` direction), `LlmId`

Detectors don't know which pass they're in — they just see the messages. This means a detector like `SEC-23 PiiLeakage` works equivalently on inbound prompts and outbound responses.

## Aggregation

After every detector runs, `DetectionPipeline` produces a `PipelineResult`:

```csharp
public sealed record PipelineResult(
    ThreatRiskScore Score,           // 0–100, aggregate
    IReadOnlyList<DetectionResult> Detections);   // every firing detection
```

`MaxSeverity` is derived from `Detections` (the highest severity any detector emitted). `Score` is the aggregate — see [Severity model](./severity-model) for the formula.

## What this design buys you

- **Zero LLM round-trip cost for rule-based threats** — `SEC-01 PromptInjection`, `SEC-23 PiiLeakage`, etc. fire in microseconds. If they quarantine, the LLM call is skipped entirely.
- **Bidirectional coverage** — many threats hide in *responses* (credential leaks, PII the model dredged up from training data, hallucinated fake citations). Pass 2 catches them.
- **Per-call audit trail** — both passes write audit entries. Investigation tools see the full request/response timeline.
- **Composable** — `SentinelChatClient` is just an `IChatClient` decorator. Stack it with rate-limiters, retries, caching, etc., in any order.

## Performance budget

| Component | Typical cost per call |
|---|---|
| Rule-based detectors (~25 of 55) | &lt;100 µs total, parallel |
| Semantic detectors (~30 of 55) | 1 ms per detector if embeddings cached, 50–500 ms uncached |
| LLM-escalation detectors (rare hits only) | full LLM round-trip — ~200–2000 ms |
| Intervention engine | &lt;10 µs |
| Audit append (`RingBufferAuditStore`) | &lt;5 µs |
| Audit append (`SqliteAuditStore`) | ~100–500 µs |
| Audit forwarder fan-out | async, off-path |

The hot path with embeddings cached is sub-millisecond. With no embedding generator configured (rule-based only), the overhead is below 200 µs per pass.

See [Detection pipeline](./detection-pipeline) for the parallel-fan-out internals and the `Configure<T>` clamp pass that runs between detection and escalation.

## Streaming

`GetStreamingResponseAsync` follows the same two-pass shape:

1. Pass 1 runs on the request before any tokens flow.
2. The inner streaming call begins.
3. Pass 2 runs **once on the fully-assembled response** after the stream completes.

There's no per-token scanning — that would require state-tracking detectors and the round-trip cost would dominate. Per-token detection is on the backlog if a real use case surfaces.

## Next: [Detection pipeline](./detection-pipeline)
