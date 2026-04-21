# OpenTelemetry Integration + Alert Deduplication Design

**Goal:** Add production-grade observability (spans, metrics) and alert deduplication to AI.Sentinel using ZeroAlloc.Telemetry for zero-boilerplate OTel proxy generation.

**Architecture:** ZeroAlloc.Telemetry generates instrumented proxies for `IDetectionPipeline`, `IAuditStore`, and `IAlertSink`. `SentinelPipeline.ScanAsync` enriches spans with domain-specific tags and maintains a per-severity threat counter. A `DeduplicatingAlertSink` decorator suppresses repeated alerts for the same detector in the same session, with an optional time-window override.

**Tech Stack:** ZeroAlloc.Telemetry (source generator), `System.Diagnostics.ActivitySource`, `System.Diagnostics.Metrics.Meter`, BCL `ConcurrentDictionary`.

---

## Architecture

Five components, all additive — no existing public API is removed.

### 1. `IDetectionPipeline` (new interface)

Extracted from `DetectionPipeline`. Annotated with `[Instrument("ai.sentinel")]` so the generator emits `DetectionPipelineInstrumented`. `SentinelPipeline` and `SentinelChatClient` take `IDetectionPipeline` instead of the concrete class.

### 2. ZeroAlloc.Telemetry annotations on existing interfaces

`IAuditStore` and `IAlertSink` receive `[Instrument("ai.sentinel")]` plus method-level `[Trace]`, `[Count]`, `[Histogram]` annotations. The generator emits `AuditStoreInstrumented` and `AlertSinkInstrumented` proxies. DI registers these proxies; callers are unaffected.

### 3. Span enrichment + per-severity counter in `SentinelPipeline`

After `IDetectionPipeline.RunAsync` returns, `ScanAsync` enriches `Activity.Current` with domain tags and increments a static `Counter<long>` per detection.

### 4. `SessionId` added to `SentinelError.ThreatDetected`

Required for session-scoped deduplication. Also improves webhook payload correlation.

### 5. `DeduplicatingAlertSink`

`IAlertSink` decorator. Always active (session-scoped by default). Wraps the instrumented sink. Suppressed alerts emit a `sentinel.alerts.suppressed` counter.

### DI stack

```
SentinelPipeline
  → DeduplicatingAlertSink           ← suppression counter
      → AlertSinkInstrumented        ← send count + trace (generated)
          → WebhookAlertSink / NullAlertSink
```

---

## OTel Annotations

### `IDetectionPipeline` (new file: `src/AI.Sentinel/Detection/IDetectionPipeline.cs`)

```csharp
[Instrument("ai.sentinel")]
public interface IDetectionPipeline
{
    [Trace("sentinel.scan")]
    [Count("sentinel.scans")]
    [Histogram("sentinel.scan.ms")]
    ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct);
}
```

`DetectionPipeline` implements `IDetectionPipeline`. No logic changes.

### `IAuditStore` (modify `src/AI.Sentinel/Audit/IAuditStore.cs`)

```csharp
[Instrument("ai.sentinel")]
public interface IAuditStore
{
    [Trace("audit.append")]
    [Count("audit.entries")]
    [Histogram("audit.append.ms")]
    ValueTask AppendAsync(AuditEntry entry, CancellationToken ct);
}
```

### `IAlertSink` (modify `src/AI.Sentinel/Alerts/IAlertSink.cs`)

```csharp
[Instrument("ai.sentinel")]
public interface IAlertSink
{
    [Trace("alert.send")]
    [Count("alert.sends")]
    ValueTask SendAsync(SentinelError error, CancellationToken ct);
}
```

No `[Histogram]` on `SendAsync` — fire-and-forget; duration is not meaningful on the caller side.

### Span enrichment in `SentinelPipeline.ScanAsync`

Added after `RunAsync` returns, before intervention logic:

```csharp
Activity.Current?.SetTag("sentinel.severity", pipelineResult.MaxSeverity.ToString());
Activity.Current?.SetTag("sentinel.is_clean", pipelineResult.IsClean);
Activity.Current?.SetTag("sentinel.threat_count", pipelineResult.Detections.Count);
Activity.Current?.SetTag("sentinel.top_detector",
    pipelineResult.Detections.MaxBy(d => d.Severity)?.DetectorId.ToString());
```

### Per-severity counter in `SentinelPipeline`

```csharp
private static readonly Meter _meter = new("ai.sentinel");
private static readonly Counter<long> _threats = _meter.CreateCounter<long>("sentinel.threats");

// in ScanAsync, when !pipelineResult.IsClean:
foreach (var d in pipelineResult.Detections)
    _threats.Add(1, new TagList { ["severity"] = d.Severity.ToString(), ["detector"] = d.DetectorId.ToString() });
```

---

## Alert Deduplication

### `SentinelError.ThreatDetected` change

```csharp
public sealed record ThreatDetected(DetectionResult Result, SentinelAction Action, SessionId Session) : SentinelError;
```

`SentinelPipeline.ScanAsync` passes `sessionId` (already in scope) when constructing the error. `WebhookAlertSink.AlertPayload` gains a `Session` field.

### `DeduplicatingAlertSink` (new file: `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`)

```csharp
public sealed class DeduplicatingAlertSink(IAlertSink inner, TimeSpan? window = null) : IAlertSink
{
    private static readonly Meter _meter = new("ai.sentinel");
    private static readonly Counter<long> _suppressed =
        _meter.CreateCounter<long>("sentinel.alerts.suppressed");

    private readonly ConcurrentDictionary<(string DetectorId, string SessionId), DateTimeOffset> _seen = new();

    public ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        if (error is not SentinelError.ThreatDetected t)
            return inner.SendAsync(error, ct);  // PipelineFailure always passes through

        var key = (t.Result.DetectorId.ToString(), t.Session.ToString());
        var expiry = window is null ? DateTimeOffset.MaxValue : DateTimeOffset.UtcNow + window.Value;

        if (!_seen.TryAdd(key, expiry))
        {
            if (_seen.TryGetValue(key, out var existing) && existing > DateTimeOffset.UtcNow)
            {
                _suppressed.Add(1, new TagList { ["detector"] = key.DetectorId });
                return ValueTask.CompletedTask;
            }
            _seen[key] = expiry;  // window expired — reset
        }

        return inner.SendAsync(error, ct);
    }
}
```

### `SentinelOptions` addition

```csharp
/// <summary>Suppression window for repeated alerts from the same detector in the same session.
/// Null (default) = suppress for the entire session lifetime. Set to suppress for a fixed duration.</summary>
public TimeSpan? AlertDeduplicationWindow { get; set; }
```

### DI wiring in `AddAISentinel`

```csharp
services.AddSingleton<IAlertSink>(sp => {
    var opts = sp.GetRequiredService<SentinelOptions>();
    IAlertSink raw = opts.AlertWebhook is not null
        ? new WebhookAlertSink(opts.AlertWebhook)
        : NullAlertSink.Instance;
    return new DeduplicatingAlertSink(
        new AlertSinkInstrumented(raw),
        opts.AlertDeduplicationWindow);
});
```

---

## Testing

### OTel — span capture via `ActivityListener`

```csharp
var activities = new List<Activity>();
using var listener = new ActivityListener
{
    ShouldListenTo = s => s.Name == "ai.sentinel",
    Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
    ActivityStopped = activities.Add
};
ActivitySource.AddActivityListener(listener);

await pipeline.RunAsync(ctx, default);

var span = Assert.Single(activities, a => a.OperationName == "sentinel.scan");
Assert.Equal("Clean", span.GetTagItem("sentinel.severity")?.ToString());
```

### OTel — metric capture via `MeterListener`

```csharp
var measurements = new List<(string Name, long Value, KeyValuePair<string, object?>[] Tags)>();
using var listener = new MeterListener();
listener.InstrumentPublished = (instrument, l) =>
{
    if (instrument.Meter.Name == "ai.sentinel") l.EnableMeasurementEvents(instrument);
};
listener.SetMeasurementEventCallback<long>((inst, val, tags, _) =>
    measurements.Add((inst.Name, val, tags.ToArray())));
listener.Start();

// trigger threat detection ...

Assert.Contains(measurements, m => m.Name == "sentinel.threats"
    && m.Tags.Any(t => t.Key == "severity" && t.Value?.ToString() == "Critical"));
```

### Deduplication tests (`DeduplicatingAlertSinkTests`)

- `SameDetectorSameSession_SecondAlert_IsSuppressed` — send twice with same key, inner sink called once
- `SameDetectorDifferentSession_BothAlerts_PassThrough` — different `SessionId`, both reach inner
- `TimeWindow_AfterExpiry_AlertPassesThrough` — 100ms window, wait 150ms, second alert passes through
- `PipelineFailure_NeverSuppressed` — `PipelineFailure` errors always reach inner sink
- `SuppressedAlert_IncrementsCounter` — `MeterListener` confirms `sentinel.alerts.suppressed` incremented

### Existing tests to update

- `SentinelErrorTests` — pass `SessionId` in `ThreatDetected` constructor
- `SentinelPipelineTests` — update stubs that construct `ThreatDetected`
- `AlertSinkTests` — update `ThreatDetected` constructors

---

## Files Changed

| Action | File |
|---|---|
| New | `src/AI.Sentinel/Detection/IDetectionPipeline.cs` |
| New | `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs` |
| Modify | `src/AI.Sentinel/Detection/DetectionPipeline.cs` — implement `IDetectionPipeline` |
| Modify | `src/AI.Sentinel/Audit/IAuditStore.cs` — add `[Instrument]` annotations |
| Modify | `src/AI.Sentinel/Alerts/IAlertSink.cs` — add `[Instrument]` annotations |
| Modify | `src/AI.Sentinel/SentinelError.cs` — add `SessionId Session` to `ThreatDetected` |
| Modify | `src/AI.Sentinel/SentinelPipeline.cs` — `IDetectionPipeline`, span enrichment, threat counter |
| Modify | `src/AI.Sentinel/SentinelChatClient.cs` — `IDetectionPipeline` in constructor |
| Modify | `src/AI.Sentinel/SentinelOptions.cs` — add `AlertDeduplicationWindow` |
| Modify | `src/AI.Sentinel/ServiceCollectionExtensions.cs` — wire instrumented proxies + dedup |
| Modify | `src/AI.Sentinel/Alerts/WebhookAlertSink.cs` — add `Session` to `AlertPayload` |
| Modify | `src/AI.Sentinel/AI.Sentinel.csproj` — add ZeroAlloc.Telemetry packages |
| New | `tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs` |
| Modify | `tests/AI.Sentinel.Tests/SentinelErrorTests.cs` — update constructors |
| Modify | `tests/AI.Sentinel.Tests/SentinelPipelineTests.cs` — update constructors |
| Modify | `tests/AI.Sentinel.Tests/Alerts/AlertSinkTests.cs` — update constructors |
