# OpenTelemetry + Alert Deduplication Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add zero-boilerplate OpenTelemetry instrumentation (spans + metrics) and session-scoped alert deduplication to AI.Sentinel using ZeroAlloc.Telemetry source generation.

**Architecture:** ZeroAlloc.Telemetry generates instrumented proxy classes for `IDetectionPipeline` (new), `IAuditStore`, and `IAlertSink`. `SentinelPipeline.ScanAsync` enriches spans via `Activity.Current` and increments a per-severity `Counter<long>`. A new `DeduplicatingAlertSink` decorator suppresses repeated alerts for the same `(DetectorId, SessionId)` pair — session-scoped by default, time-windowed when `opts.AlertDeduplicationWindow` is set. `SentinelError.ThreatDetected` gains a `SessionId Session` parameter so the dedup key is available at the sink boundary.

**Tech Stack:** ZeroAlloc.Telemetry 1.x (source generator), `System.Diagnostics.ActivitySource`, `System.Diagnostics.Metrics.Meter`, BCL `ConcurrentDictionary`, xUnit `ActivityListener` + `MeterListener` for test assertions.

**Design doc:** `docs/plans/2026-04-21-otel-alert-dedup-design.md`

---

### Task 1: Add ZeroAlloc.Telemetry package reference

**Files:**
- Modify: `src/AI.Sentinel/AI.Sentinel.csproj`

**Step 1: Add the package reference**

In the `ItemGroup` that contains `ZeroAlloc.Inject` (around line 14), add:

```xml
<PackageReference Include="ZeroAlloc.Telemetry" Version="1.*" />
```

`ZeroAlloc.Telemetry` bundles its source generator — no separate `OutputItemType="Analyzer"` reference needed, unlike `ZeroAlloc.Inject`.

**Step 2: Verify the build resolves**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Debug
```

Expected: `Build succeeded. 0 Warning(s) 0 Error(s)`

**Step 3: Commit**

```bash
git add src/AI.Sentinel/AI.Sentinel.csproj
git commit -m "feat: add ZeroAlloc.Telemetry package reference"
```

---

### Task 2: Extract IDetectionPipeline and annotate all three interfaces

**Files:**
- Create: `src/AI.Sentinel/Detection/IDetectionPipeline.cs`
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs` (class declaration only)
- Modify: `src/AI.Sentinel/Audit/IAuditStore.cs`
- Modify: `src/AI.Sentinel/Alerts/IAlertSink.cs`

**Step 1: Create IDetectionPipeline**

Create `src/AI.Sentinel/Detection/IDetectionPipeline.cs`:

```csharp
using ZeroAlloc.Telemetry;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>Runs a detection pipeline over a <see cref="SentinelContext"/> and returns the aggregated result.</summary>
[Instrument("ai.sentinel")]
public interface IDetectionPipeline
{
    /// <summary>Runs all enabled detectors against <paramref name="ctx"/> and returns the aggregated <see cref="PipelineResult"/>.</summary>
    [Trace("sentinel.scan")]
    [Count("sentinel.scans")]
    [Histogram("sentinel.scan.ms")]
    ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct);
}
```

**Step 2: Make DetectionPipeline implement IDetectionPipeline**

In `src/AI.Sentinel/Detection/DetectionPipeline.cs`, change line 8:

```csharp
// BEFORE:
public sealed class DetectionPipeline

// AFTER:
public sealed class DetectionPipeline : IDetectionPipeline
```

**Step 3: Annotate IAuditStore**

Replace `src/AI.Sentinel/Audit/IAuditStore.cs` content:

```csharp
using ZeroAlloc.Telemetry;

namespace AI.Sentinel.Audit;

[Instrument("ai.sentinel")]
public interface IAuditStore
{
    [Trace("audit.append")]
    [Count("audit.entries")]
    [Histogram("audit.append.ms")]
    ValueTask AppendAsync(AuditEntry entry, CancellationToken ct);
    IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct);
}
```

`QueryAsync` has no annotation — the generated proxy will forward it as a pass-through.

**Step 4: Annotate IAlertSink**

In `src/AI.Sentinel/Alerts/IAlertSink.cs`, add `using ZeroAlloc.Telemetry;` and the attributes. The existing XML doc comments stay. The interface becomes:

```csharp
using ZeroAlloc.Telemetry;

namespace AI.Sentinel.Alerts;

/// <summary>Dispatches alert notifications when a threat is detected or the pipeline fails.</summary>
/// <remarks>Implementations are expected to be fire-and-forget; errors must be swallowed so they never surface to the caller.</remarks>
[Instrument("ai.sentinel")]
public interface IAlertSink
{
    /// <summary>Sends an alert for the given <paramref name="error"/> to the underlying notification channel.</summary>
    /// <param name="error">The sentinel error that triggered the alert.</param>
    /// <param name="ct">Cancellation token for the send operation.</param>
    [Trace("alert.send")]
    [Count("alert.sends")]
    ValueTask SendAsync(SentinelError error, CancellationToken ct);
}
```

**Step 5: Build — verify generator emits the three proxy types**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Debug
```

Expected: `Build succeeded. 0 Error(s)` — the generator emits `DetectionPipelineInstrumented`, `AuditStoreInstrumented`, and `AlertSinkInstrumented` as sealed proxy classes in the `obj/` folder.

**Step 6: Run existing tests to confirm nothing is broken**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug
```

Expected: All tests pass (the interfaces themselves haven't changed behaviour).

**Step 7: Commit**

```bash
git add src/AI.Sentinel/Detection/IDetectionPipeline.cs \
        src/AI.Sentinel/Detection/DetectionPipeline.cs \
        src/AI.Sentinel/Audit/IAuditStore.cs \
        src/AI.Sentinel/Alerts/IAlertSink.cs
git commit -m "feat: extract IDetectionPipeline; annotate interfaces for ZeroAlloc.Telemetry generation"
```

---

### Task 3: SentinelPipeline and SentinelChatClient: DetectionPipeline → IDetectionPipeline

**Files:**
- Modify: `src/AI.Sentinel/SentinelPipeline.cs` (constructor parameter type)
- Modify: `src/AI.Sentinel/SentinelChatClient.cs` (constructor parameter type)

**Background:** Both classes currently take `DetectionPipeline` (concrete class). Changing to `IDetectionPipeline` allows DI to inject the instrumented proxy. Since `DetectionPipeline : IDetectionPipeline`, all existing test helpers that pass `new DetectionPipeline(...)` continue to compile and work without changes.

**Step 1: Update SentinelPipeline constructor**

In `src/AI.Sentinel/SentinelPipeline.cs`, change the constructor parameter on line 16:

```csharp
// BEFORE:
public sealed class SentinelPipeline(
    IChatClient innerClient,
    DetectionPipeline pipeline,

// AFTER:
public sealed class SentinelPipeline(
    IChatClient innerClient,
    IDetectionPipeline pipeline,
```

Also add `using AI.Sentinel.Detection;` if not already present.

**Step 2: Update SentinelChatClient constructor**

In `src/AI.Sentinel/SentinelChatClient.cs`, change the constructor parameter:

```csharp
// BEFORE:
    DetectionPipeline pipeline,

// AFTER:
    IDetectionPipeline pipeline,
```

**Step 3: Run tests — all must pass**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug
```

Expected: All tests pass. `DetectionPipeline` implements `IDetectionPipeline` so all existing test helpers compile.

**Step 4: Commit**

```bash
git add src/AI.Sentinel/SentinelPipeline.cs src/AI.Sentinel/SentinelChatClient.cs
git commit -m "refactor: SentinelPipeline and SentinelChatClient take IDetectionPipeline"
```

---

### Task 4: Add SessionId to SentinelError.ThreatDetected

**Files:**
- Modify: `src/AI.Sentinel/SentinelError.cs`
- Modify: `src/AI.Sentinel/SentinelPipeline.cs` (two call sites)
- Modify: `tests/AI.Sentinel.Tests/SentinelErrorTests.cs`
- Modify: `tests/AI.Sentinel.Tests/Alerts/AlertSinkTests.cs` (3 call sites)

**Background:** `DeduplicatingAlertSink` needs `SessionId` to key per-session suppression. Adding it to `ThreatDetected` also enriches the webhook payload. `sessionId` is already in scope in `SentinelPipeline.ScanAsync` where the error is constructed.

**Step 1: Write the failing test**

In `tests/AI.Sentinel.Tests/SentinelErrorTests.cs`, add:

```csharp
[Fact]
public void ThreatDetected_ExposesSessionId()
{
    var sessionId = SessionId.New();
    var error = new SentinelError.ThreatDetected(
        DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test"),
        SentinelAction.Quarantine,
        sessionId);
    Assert.Equal(sessionId, error.Session);
}
```

You'll need `using AI.Sentinel.Domain;` if not already present.

**Step 2: Run to confirm it fails**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug --filter "ThreatDetected_ExposesSessionId"
```

Expected: FAIL — `ThreatDetected` has no `Session` parameter.

**Step 3: Add Session to ThreatDetected**

In `src/AI.Sentinel/SentinelError.cs`, change line 13:

```csharp
// BEFORE:
public sealed record ThreatDetected(DetectionResult Result, SentinelAction Action) : SentinelError;

// AFTER:
/// <summary>Indicates a threat was detected and an action was taken.</summary>
/// <param name="Result">The highest-severity detection that triggered this error.</param>
/// <param name="Action">The action taken in response to the detection.</param>
/// <param name="Session">The session in which the threat was detected.</param>
public sealed record ThreatDetected(DetectionResult Result, SentinelAction Action, SessionId Session) : SentinelError;
```

**Step 4: Fix SentinelPipeline — two call sites in ScanAsync**

In `src/AI.Sentinel/SentinelPipeline.cs`, `ScanAsync` already has `SessionId sessionId` as a parameter (line 63). Update both places where `ThreatDetected` is constructed:

Alert sink path (around line 79):
```csharp
// BEFORE:
_ = alertSink.SendAsync(new SentinelError.ThreatDetected(top, action), CancellationToken.None).AsTask();

// AFTER:
_ = alertSink.SendAsync(new SentinelError.ThreatDetected(top, action, sessionId), CancellationToken.None).AsTask();
```

Quarantine catch block (around line 94):
```csharp
// BEFORE:
return new SentinelError.ThreatDetected(top, action);

// AFTER:
return new SentinelError.ThreatDetected(top, action, sessionId);
```

**Step 5: Fix all broken test call sites**

In `tests/AI.Sentinel.Tests/SentinelErrorTests.cs` line 14:
```csharp
// BEFORE:
var error = new SentinelError.ThreatDetected(result, SentinelAction.Quarantine);

// AFTER:
var error = new SentinelError.ThreatDetected(result, SentinelAction.Quarantine, SessionId.New());
```

In `tests/AI.Sentinel.Tests/Alerts/AlertSinkTests.cs` — update all three `ThreatDetected` constructions (lines 13, 32, 57) to add `SessionId.New()` as the third argument.

**Step 6: Run all tests**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug
```

Expected: All tests pass, including the new `ThreatDetected_ExposesSessionId`.

**Step 7: Commit**

```bash
git add src/AI.Sentinel/SentinelError.cs \
        src/AI.Sentinel/SentinelPipeline.cs \
        tests/AI.Sentinel.Tests/SentinelErrorTests.cs \
        tests/AI.Sentinel.Tests/Alerts/AlertSinkTests.cs
git commit -m "feat: add SessionId to SentinelError.ThreatDetected for deduplication and webhook correlation"
```

---

### Task 5: Span enrichment and per-severity Counter in SentinelPipeline

**Files:**
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`

**Background:** The `DetectionPipelineInstrumented` proxy opens an `Activity` span around `RunAsync`. After `RunAsync` returns, `SentinelPipeline.ScanAsync` can enrich `Activity.Current` with domain tags. A static `Counter<long>` tracks threat counts per severity+detector combination — no OTel SDK needed, just BCL `System.Diagnostics.Metrics`.

**Step 1: Add using directives**

At the top of `src/AI.Sentinel/SentinelPipeline.cs`, add:

```csharp
using System.Diagnostics;
using System.Diagnostics.Metrics;
```

**Step 2: Add static Meter and Counter fields**

Inside the `SentinelPipeline` class, before the constructor, add:

```csharp
private static readonly Meter _meter = new("ai.sentinel");
private static readonly Counter<long> _threats = _meter.CreateCounter<long>("sentinel.threats");
```

**Step 3: Add span enrichment and counter increments in ScanAsync**

In `ScanAsync`, after `await AppendAuditAsync(...)` and before the `if (pipelineResult.IsClean) return null;` check, add:

```csharp
Activity.Current?.SetTag("sentinel.severity", pipelineResult.MaxSeverity.ToString());
Activity.Current?.SetTag("sentinel.is_clean", pipelineResult.IsClean);
Activity.Current?.SetTag("sentinel.threat_count", pipelineResult.Detections.Count);
Activity.Current?.SetTag("sentinel.top_detector",
    pipelineResult.Detections.MaxBy(d => d.Severity)?.DetectorId.ToString());
```

After the `if (pipelineResult.IsClean) return null;` line, add the counter:

```csharp
foreach (var d in pipelineResult.Detections)
    _threats.Add(1, new TagList { ["severity"] = d.Severity.ToString(), ["detector"] = d.DetectorId.ToString() });
```

**Step 4: Build and run tests**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug
```

Expected: All tests pass. (OTel tests that verify spans/metrics are written in Task 10.)

**Step 5: Commit**

```bash
git add src/AI.Sentinel/SentinelPipeline.cs
git commit -m "feat: enrich sentinel.scan spans with severity tags; add sentinel.threats counter per severity"
```

---

### Task 6: Add Session field to WebhookAlertSink.AlertPayload

**Files:**
- Modify: `src/AI.Sentinel/Alerts/WebhookAlertSink.cs`
- Modify: `tests/AI.Sentinel.Tests/Alerts/AlertSinkTests.cs`

**Step 1: Update AlertPayload record and switch expression**

In `src/AI.Sentinel/Alerts/WebhookAlertSink.cs`, change the `AlertPayload` record (bottom of file):

```csharp
// BEFORE:
private sealed record AlertPayload(
    string Type,
    string Severity,
    string Detector,
    string Reason,
    string Action);

// AFTER:
private sealed record AlertPayload(
    string Type,
    string Severity,
    string Detector,
    string Reason,
    string Action,
    string Session);
```

Update the switch expression for `ThreatDetected`:

```csharp
// BEFORE:
SentinelError.ThreatDetected t => new AlertPayload(
    "ThreatDetected",
    t.Result.Severity.ToString(),
    t.Result.DetectorId.ToString(),
    t.Result.Reason,
    t.Action.ToString()),

// AFTER:
SentinelError.ThreatDetected t => new AlertPayload(
    "ThreatDetected",
    t.Result.Severity.ToString(),
    t.Result.DetectorId.ToString(),
    t.Result.Reason,
    t.Action.ToString(),
    t.Session.ToString()),
```

Update `PipelineFailure` and the fallback case — add `"n/a"` as the last argument to both.

**Step 2: Update the webhook payload test**

In `tests/AI.Sentinel.Tests/Alerts/AlertSinkTests.cs`, in `WebhookAlertSink_ThreatDetected_PostsCorrectJsonPayload`, the `ThreatDetected` construction already has `SessionId.New()` (fixed in Task 4). Add an assertion for the session field:

```csharp
Assert.Contains("\"session\":", capturedBody, StringComparison.OrdinalIgnoreCase);
```

**Step 3: Run tests**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug
```

Expected: All tests pass.

**Step 4: Commit**

```bash
git add src/AI.Sentinel/Alerts/WebhookAlertSink.cs \
        tests/AI.Sentinel.Tests/Alerts/AlertSinkTests.cs
git commit -m "feat: include SessionId in WebhookAlertSink JSON payload"
```

---

### Task 7: Wire instrumented proxies in ServiceCollectionExtensions

**Files:**
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`

**Background:** `AddAISentinel` currently registers `DetectionPipeline` as itself and `RingBufferAuditStore` as `IAuditStore`. After this task, DI serves `IDetectionPipeline` (instrumented proxy wrapping `DetectionPipeline`) and `IAuditStore` (instrumented proxy wrapping `RingBufferAuditStore`). `UseAISentinel` and `BuildSentinelPipeline` resolve `IDetectionPipeline` instead of `DetectionPipeline`.

`IAlertSink` is left alone here — the dedup + instrumentation wiring happens in Task 9.

**Step 1: Update AddAISentinel**

Replace the `DetectionPipeline` and `IAuditStore` registrations:

```csharp
// BEFORE:
services.AddSingleton<IAuditStore>(new RingBufferAuditStore(opts.AuditCapacity));
// ...
services.AddSingleton(sp =>
    new DetectionPipeline(sp.GetServices<IDetector>(), opts.EscalationClient, sp.GetService<ILogger<DetectionPipeline>>()));

// AFTER:
services.AddSingleton<IAuditStore>(
    new AuditStoreInstrumented(new RingBufferAuditStore(opts.AuditCapacity)));
// ...
services.AddSingleton<IDetectionPipeline>(sp =>
    new DetectionPipelineInstrumented(
        new DetectionPipeline(sp.GetServices<IDetector>(), opts.EscalationClient, sp.GetService<ILogger<DetectionPipeline>>())));
```

Note: `DetectionPipeline` is no longer registered as itself. `UseAISentinel` and `BuildSentinelPipeline` already resolve the interface (changed in Task 3), so they get the instrumented proxy automatically.

**Step 2: Update UseAISentinel**

```csharp
// BEFORE:
sp.GetRequiredService<DetectionPipeline>(),

// AFTER:
sp.GetRequiredService<IDetectionPipeline>(),
```

**Step 3: Update BuildSentinelPipeline**

```csharp
// BEFORE:
sp.GetRequiredService<DetectionPipeline>(),

// AFTER:
sp.GetRequiredService<IDetectionPipeline>(),
```

**Step 4: Run tests**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug
```

Expected: All tests pass — the integration tests (`BuildSentinelPipeline_IsWiredToProvidedClient`, etc.) confirm the proxies are wired correctly.

**Step 5: Commit**

```bash
git add src/AI.Sentinel/ServiceCollectionExtensions.cs
git commit -m "feat: register instrumented DetectionPipeline and AuditStore proxies in DI"
```

---

### Task 8: Add AlertDeduplicationWindow to SentinelOptions

**Files:**
- Modify: `src/AI.Sentinel/SentinelOptions.cs`

**Step 1: Write failing test**

In `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs` (check if it exists; if not, create it), add:

```csharp
[Fact]
public void AlertDeduplicationWindow_DefaultsToNull()
{
    var opts = new SentinelOptions();
    Assert.Null(opts.AlertDeduplicationWindow);
}
```

**Step 2: Run to confirm it fails**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug --filter "AlertDeduplicationWindow_DefaultsToNull"
```

Expected: FAIL — `AlertDeduplicationWindow` property does not exist.

**Step 3: Add property to SentinelOptions**

In `src/AI.Sentinel/SentinelOptions.cs`, after `AlertWebhook`, add:

```csharp
/// <summary>Suppression window for repeated alerts from the same detector in the same session.
/// <c>null</c> (default) suppresses for the entire session lifetime.
/// Set to a <see cref="TimeSpan"/> to re-alert after the window expires.</summary>
public TimeSpan? AlertDeduplicationWindow { get; set; }
```

**Step 4: Run test**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug --filter "AlertDeduplicationWindow_DefaultsToNull"
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/AI.Sentinel/SentinelOptions.cs tests/AI.Sentinel.Tests/SentinelOptionsTests.cs
git commit -m "feat: add AlertDeduplicationWindow option for configurable alert suppression"
```

---

### Task 9: Implement DeduplicatingAlertSink and wire in DI

**Files:**
- Create: `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`

**Step 1: Create DeduplicatingAlertSink**

Create `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`:

```csharp
using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace AI.Sentinel.Alerts;

/// <summary>Alert sink decorator that suppresses repeated alerts for the same detector and session.</summary>
/// <remarks>Session-scoped by default (same detector never re-alerts in the same session).
/// Set <paramref name="window"/> to re-alert after the window expires.</remarks>
public sealed class DeduplicatingAlertSink(IAlertSink inner, TimeSpan? window = null) : IAlertSink
{
    private static readonly Meter _meter = new("ai.sentinel");
    private static readonly Counter<long> _suppressed =
        _meter.CreateCounter<long>("sentinel.alerts.suppressed");

    private readonly ConcurrentDictionary<(string DetectorId, string SessionId), DateTimeOffset> _seen = new();

    public ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        // PipelineFailure errors always pass through — no session context to key on.
        if (error is not SentinelError.ThreatDetected t)
            return inner.SendAsync(error, ct);

        var key = (t.Result.DetectorId.ToString(), t.Session.ToString());
        var expiry = window is null ? DateTimeOffset.MaxValue : DateTimeOffset.UtcNow + window.Value;

        if (_seen.TryAdd(key, expiry))
            return inner.SendAsync(error, ct);  // first occurrence — send

        if (_seen.TryGetValue(key, out var existing) && existing > DateTimeOffset.UtcNow)
        {
            _suppressed.Add(1, new TagList { ["detector"] = key.DetectorId });
            return ValueTask.CompletedTask;  // within window — suppress
        }

        // Window has expired — reset and send.
        _seen[key] = expiry;
        return inner.SendAsync(error, ct);
    }
}
```

**Step 2: Wire in AddAISentinel**

In `src/AI.Sentinel/ServiceCollectionExtensions.cs`, replace the current `IAlertSink` registration:

```csharp
// BEFORE:
services.AddSingleton<IAlertSink>(opts.AlertWebhook is not null
    ? new WebhookAlertSink(opts.AlertWebhook)
    : NullAlertSink.Instance);

// AFTER:
services.AddSingleton<IAlertSink>(_ =>
{
    IAlertSink raw = opts.AlertWebhook is not null
        ? new WebhookAlertSink(opts.AlertWebhook)
        : NullAlertSink.Instance;
    return new DeduplicatingAlertSink(new AlertSinkInstrumented(raw), opts.AlertDeduplicationWindow);
});
```

**Step 3: Build**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Debug
```

Expected: Build succeeded.

**Step 4: Run tests**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug
```

Expected: All tests pass. The existing `AddAISentinel_NoAlertWebhook_RegistersNullAlertSink` test will now get a `DeduplicatingAlertSink` wrapping `AlertSinkInstrumented` wrapping `NullAlertSink` — update that test to check for `DeduplicatingAlertSink` or `IAlertSink` being registered rather than the concrete type, since the outermost type is now `DeduplicatingAlertSink`.

Specifically, update `ServiceCollectionExtensionsTests.cs`:

```csharp
// BEFORE:
Assert.IsType<NullAlertSink>(sink);

// AFTER:
Assert.IsType<DeduplicatingAlertSink>(sink);
```

And for the WebhookAlertSink test:

```csharp
// BEFORE:
Assert.IsType<WebhookAlertSink>(sink);

// AFTER:
Assert.IsType<DeduplicatingAlertSink>(sink);
```

**Step 5: Commit**

```bash
git add src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs \
        src/AI.Sentinel/ServiceCollectionExtensions.cs \
        tests/AI.Sentinel.Tests/ServiceCollectionExtensionsTests.cs
git commit -m "feat: implement DeduplicatingAlertSink; wire as outermost IAlertSink in DI"
```

---

### Task 10: Write DeduplicatingAlertSink tests

**Files:**
- Create: `tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs`

**Step 1: Create test file**

Create `tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs`:

```csharp
using AI.Sentinel.Alerts;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using System.Diagnostics.Metrics;
using Xunit;

namespace AI.Sentinel.Tests.Alerts;

public class DeduplicatingAlertSinkTests
{
    private static SentinelError.ThreatDetected MakeThreat(string detectorId, SessionId sessionId) =>
        new(DetectionResult.WithSeverity(new DetectorId(detectorId), Severity.High, "test"),
            SentinelAction.Alert,
            sessionId);

    [Fact]
    public async Task SameDetectorSameSession_SecondAlert_IsSuppressed()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);
        var session = SessionId.New();
        var threat = MakeThreat("SEC-01", session);

        await sink.SendAsync(threat, default);
        await sink.SendAsync(threat, default);

        Assert.Equal(1, inner.CallCount);
    }

    [Fact]
    public async Task SameDetectorDifferentSession_BothAlerts_PassThrough()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);

        await sink.SendAsync(MakeThreat("SEC-01", SessionId.New()), default);
        await sink.SendAsync(MakeThreat("SEC-01", SessionId.New()), default);

        Assert.Equal(2, inner.CallCount);
    }

    [Fact]
    public async Task TimeWindow_AfterExpiry_AlertPassesThrough()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner, window: TimeSpan.FromMilliseconds(50));
        var session = SessionId.New();

        await sink.SendAsync(MakeThreat("SEC-01", session), default);
        await Task.Delay(100); // wait for window to expire
        await sink.SendAsync(MakeThreat("SEC-01", session), default);

        Assert.Equal(2, inner.CallCount);
    }

    [Fact]
    public async Task PipelineFailure_NeverSuppressed()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);
        var failure = new SentinelError.PipelineFailure("test error");

        await sink.SendAsync(failure, default);
        await sink.SendAsync(failure, default);

        Assert.Equal(2, inner.CallCount);
    }

    [Fact]
    public async Task SuppressedAlert_IncrementsCounter()
    {
        var measurements = new List<long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == "ai.sentinel" && instrument.Name == "sentinel.alerts.suppressed")
                l.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => measurements.Add(val));
        listener.Start();

        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);
        var session = SessionId.New();

        await sink.SendAsync(MakeThreat("SEC-01", session), default);
        await sink.SendAsync(MakeThreat("SEC-01", session), default); // suppressed

        Assert.Single(measurements);
        Assert.Equal(1L, measurements[0]);
    }

    private sealed class RecordingAlertSink : IAlertSink
    {
        private int _callCount;
        public int CallCount => _callCount;

        public ValueTask SendAsync(SentinelError error, CancellationToken ct)
        {
            Interlocked.Increment(ref _callCount);
            return ValueTask.CompletedTask;
        }
    }
}
```

**Step 2: Run to confirm tests pass**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug --filter "DeduplicatingAlertSinkTests"
```

Expected: All 5 tests pass.

**Step 3: Commit**

```bash
git add tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs
git commit -m "test: DeduplicatingAlertSink — suppression, pass-through, expiry, and metric counter"
```

---

### Task 11: Write OTel span and metric tests

**Files:**
- Create: `tests/AI.Sentinel.Tests/Telemetry/TelemetryTests.cs`

**Step 1: Create test file**

Create `tests/AI.Sentinel.Tests/Telemetry/TelemetryTests.cs`:

```csharp
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests.Telemetry;

public class TelemetryTests
{
    private static SentinelPipeline BuildWithDetector(IDetector detector)
    {
        var opts = new SentinelOptions();
        IDetectionPipeline pipeline = new DetectionPipelineInstrumented(
            new DetectionPipeline([detector], null));
        IAuditStore audit = new AuditStoreInstrumented(new RingBufferAuditStore(100));
        var engine = new InterventionEngine(opts, null);
        return new SentinelPipeline(new NoOpChatClient(), pipeline, audit, engine, opts);
    }

    [Fact]
    public async Task SentinelScan_EmitsActivitySpan()
    {
        var activities = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == "ai.sentinel",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activities.Add
        };
        ActivitySource.AddActivityListener(listener);

        var pipeline = BuildWithDetector(new AlwaysCleanDetector());
        _ = await pipeline.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "hello")], null, default);

        var span = Assert.Single(activities, a => a.OperationName == "sentinel.scan");
        Assert.Equal("Clean", span.GetTagItem("sentinel.severity")?.ToString());
        Assert.Equal("True", span.GetTagItem("sentinel.is_clean")?.ToString());
    }

    [Fact]
    public async Task ThreatDetected_IncrementsSentinelThreatsCounter()
    {
        var measurements = new List<(string Severity, string Detector)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == "ai.sentinel" && instrument.Name == "sentinel.threats")
                l.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            var severity = tags.FirstOrDefault(t => t.Key == "severity").Value?.ToString() ?? "";
            var detector = tags.FirstOrDefault(t => t.Key == "detector").Value?.ToString() ?? "";
            measurements.Add((severity, detector));
        });
        listener.Start();

        var pipeline = BuildWithDetector(new AlwaysCriticalDetector());
        _ = await pipeline.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "hostile")], null, default);

        Assert.Contains(measurements, m => m.Severity == "Critical" && m.Detector == "TEST-01");
    }

    private sealed class AlwaysCleanDetector : IDetector
    {
        public DetectorId Id => new("CLEAN-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(Id));
    }

    private sealed class AlwaysCriticalDetector : IDetector
    {
        public DetectorId Id => new("TEST-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "forced critical"));
    }

    private sealed class NoOpChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "ok")]));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
            => throw new NotSupportedException();
        public ChatClientMetadata Metadata => new("noop", null, null);
        public object? GetService(Type t, object? k = null) => null;
        public void Dispose() { }
    }
}
```

**Note:** `DetectionPipelineInstrumented` and `AuditStoreInstrumented` are the source-generated proxy types. They live in the `AI.Sentinel.Detection` and `AI.Sentinel.Audit` namespaces respectively (check generated files in `obj/` if the namespace is unclear — the generator strips the leading `I` and appends `Instrumented`).

**Step 2: Run tests**

```bash
dotnet test tests/AI.Sentinel.Tests -c Debug --filter "TelemetryTests"
```

Expected: Both tests pass.

**Step 3: Commit**

```bash
git add tests/AI.Sentinel.Tests/Telemetry/TelemetryTests.cs
git commit -m "test: OTel span and metric capture via ActivityListener and MeterListener"
```

---

### Task 12: Final build and full test suite

**Step 1: Release build across all targets**

```bash
dotnet build -c Release
```

Expected: `Build succeeded. 0 Error(s)` across `net8.0` and `net9.0` (or whatever targets are active in `Directory.Build.props`).

**Step 2: Full test suite**

```bash
dotnet test -c Release
```

Expected: All tests pass on all target frameworks. Count should be the prior count + the new deduplication and telemetry tests.

**Step 3: Commit if any fixes were needed**

If any issues surfaced, fix them and commit. Otherwise no commit needed.
