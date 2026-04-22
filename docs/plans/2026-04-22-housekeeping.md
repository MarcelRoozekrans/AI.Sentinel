# Housekeeping Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Centralize the scattered `Meter` declarations into `SentinelMetrics`, and stop `_seen` and `_rateLimiters` from growing unbounded via lazy time-based eviction gated by `SessionIdleTimeout`.

**Architecture:** New `internal static class SentinelMetrics` owns the shared `Meter("ai.sentinel")` and all hand-written counters. Both dictionaries keep their `ConcurrentDictionary` shape (zero-alloc hot path) and gain a sweep that runs every 256 writes to remove stale entries based on last-use timestamp.

**Tech Stack:** `System.Diagnostics.Metrics.Meter`, `ConcurrentDictionary`, `Interlocked`, `Environment.TickCount64`.

---

## Context: key facts

- `SentinelPipeline` at `src/AI.Sentinel/SentinelPipeline.cs`:
  - Lines 26–30: owns `_meter`, `_threats`, `_rateLimited` counters + `_activitySource`
  - Line 31: `_rateLimiters = new ConcurrentDictionary<string, RateLimiter>(StringComparer.Ordinal)`
  - Lines 186–200: `CheckRateLimit(ChatOptions?)` method
- `DeduplicatingAlertSink` at `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`:
  - Lines 15–17: owns `_meter` and `_suppressed` counter
  - Line 19: `_seen = new ConcurrentDictionary<(string DetectorId, string SessionId), DateTimeOffset>()`
  - Constructor signature: `(IAlertSink inner, TimeSpan? window = null)`
- `SentinelOptions` at `src/AI.Sentinel/SentinelOptions.cs` already uses `[GreaterThan(0)]` on `AuditCapacity`, `MaxCallsPerSecond`, `BurstSize`. But `SentinelOptionsValidator` is hand-rolled and only validates these properties — the attribute is decorative for now.
- `ServiceCollectionExtensions.cs:25` — `new DeduplicatingAlertSink(new AlertSinkInstrumented(raw), opts.AlertDeduplicationWindow)`
- Source-generator-emitted counters from ZeroAlloc.Telemetry (`sentinel.scans`, `sentinel.scan.ms`, `audit.*`, `alert.sends`) are owned by generated proxies — do NOT migrate these; they stay in the generated code.

**Test runner:**
```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

---

## Task 1: Create `SentinelMetrics` and migrate the two consumers

Move all hand-written counters into one class. `SentinelPipeline` and `DeduplicatingAlertSink` reference `SentinelMetrics.*` — their own static `Meter` / counter fields are deleted.

**Files:**
- Create: `src/AI.Sentinel/SentinelMetrics.cs`
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`
- Modify: `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`

### Step 1: Create `SentinelMetrics.cs`

```csharp
using System.Diagnostics.Metrics;

namespace AI.Sentinel;

/// <summary>Central owner of the <c>ai.sentinel</c> meter and all hand-written counters.
/// Source-generator-emitted counters (from ZeroAlloc.Telemetry <c>[Instrument]</c> proxies)
/// live in their generated code and are not duplicated here.</summary>
internal static class SentinelMetrics
{
    internal static readonly Meter Meter = new("ai.sentinel");

    internal static readonly Counter<long> Threats =
        Meter.CreateCounter<long>("sentinel.threats");

    internal static readonly Counter<long> RateLimited =
        Meter.CreateCounter<long>("sentinel.rate_limit.exceeded");

    internal static readonly Counter<long> AlertsSuppressed =
        Meter.CreateCounter<long>("sentinel.alerts.suppressed");
}
```

### Step 2: Migrate `SentinelPipeline`

In `src/AI.Sentinel/SentinelPipeline.cs`, replace lines 26–30:

```csharp
    private static readonly Meter _meter = new("ai.sentinel");
    private static readonly Counter<long> _threats = _meter.CreateCounter<long>("sentinel.threats");
    private static readonly ActivitySource _activitySource = new("ai.sentinel");
    private static readonly Counter<long> _rateLimited =
        _meter.CreateCounter<long>("sentinel.rate_limit.exceeded");
```

With:

```csharp
    private static readonly ActivitySource _activitySource = new("ai.sentinel");
```

Then update the two usages:
- Line 155 (inside the detection loop): `_threats.Add(1, tags);` → `SentinelMetrics.Threats.Add(1, tags);`
- Line 198: `_rateLimited.Add(1, ...)` → `SentinelMetrics.RateLimited.Add(1, ...)`

Remove the `using System.Diagnostics.Metrics;` import if no other usages remain (there shouldn't be any — `ActivitySource` is in `System.Diagnostics`).

### Step 3: Migrate `DeduplicatingAlertSink`

In `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`:

Remove lines 15–17:
```csharp
    private static readonly Meter _meter = new("ai.sentinel");
    private static readonly Counter<long> _suppressed =
        _meter.CreateCounter<long>("sentinel.alerts.suppressed");
```

Update line 45 from:
```csharp
            _suppressed.Add(1, new TagList { { "detector", detectorId } });
```

To:
```csharp
            SentinelMetrics.AlertsSuppressed.Add(1, new TagList { { "detector", detectorId } });
```

Remove the unused imports (`using System.Diagnostics.Metrics;`). Keep `using System.Diagnostics;` for `TagList`.

### Step 4: Build and run full test suite

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -5
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: 0 errors, all existing tests pass (behavior unchanged — same counter names, same meter name).

### Step 5: Commit

```bash
git add src/AI.Sentinel/SentinelMetrics.cs src/AI.Sentinel/SentinelPipeline.cs src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs
git commit -m "refactor: centralize Meter and counters into SentinelMetrics"
```

---

## Task 2: Add `SessionIdleTimeout` to `SentinelOptions` + validator

**Files:**
- Modify: `src/AI.Sentinel/SentinelOptions.cs`
- Modify: `src/AI.Sentinel/SentinelOptionsValidator.cs`
- Modify: `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs`

### Step 1: Write the failing test

Add to `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs` (inside the class, after the last test):

```csharp
[Fact]
public void SessionIdleTimeout_DefaultsToOneHour()
{
    var opts = new SentinelOptions();
    Assert.Equal(TimeSpan.FromHours(1), opts.SessionIdleTimeout);
}

[Theory]
[InlineData(0)]
[InlineData(-1)]
public void SessionIdleTimeout_ZeroOrNegative_IsInvalid(int seconds)
{
    var opts = new SentinelOptions { SessionIdleTimeout = TimeSpan.FromSeconds(seconds) };
    Assert.False(new SentinelOptionsValidator().Validate(opts).IsValid);
}
```

### Step 2: Run to verify failure

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "SessionIdleTimeout" 2>&1 | tail -10
```

Expected: build error — `SessionIdleTimeout` does not exist.

### Step 3: Add the property to `SentinelOptions`

In `src/AI.Sentinel/SentinelOptions.cs`, add after the `BurstSize` property (after line 46):

```csharp
    /// <summary>Inactivity window after which per-session dedup state and rate-limiter
    /// buckets are evicted from in-memory dictionaries. Default: 1 hour.
    /// Increase for long-lived sessions; decrease for very high-cardinality session keys.</summary>
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromHours(1);
```

### Step 4: Add validation

In `src/AI.Sentinel/SentinelOptionsValidator.cs`, inside the `Validate` method, add after the `BurstSize` check:

```csharp
        if (opts.SessionIdleTimeout <= TimeSpan.Zero)
            failures.Add(new ValidationFailure
            {
                ErrorMessage = "SessionIdleTimeout must be greater than TimeSpan.Zero",
                ErrorCode    = "GreaterThan"
            });
```

### Step 5: Run tests

```bash
dotnet test tests/AI.Sentinel.Tests -v m --filter "SessionIdleTimeout" 2>&1 | tail -10
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: new tests pass, all other tests still pass.

### Step 6: Commit

```bash
git add src/AI.Sentinel/SentinelOptions.cs src/AI.Sentinel/SentinelOptionsValidator.cs tests/AI.Sentinel.Tests/SentinelOptionsTests.cs
git commit -m "feat: add SessionIdleTimeout option with validation"
```

---

## Task 3: Add `_seen` eviction to `DeduplicatingAlertSink`

Add `sessionIdleTimeout` parameter. Change the `null window` expiry to use it. Sweep expired entries every 256 writes.

**Files:**
- Modify: `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`
- Modify: `tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs`

### Step 1: Write the failing tests

Add to `tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs` (inside the class):

```csharp
[Fact]
public async Task SessionScoped_AfterIdleTimeout_AlertPassesThrough()
{
    var inner = new RecordingSink();
    var sink = new DeduplicatingAlertSink(inner, window: null, sessionIdleTimeout: TimeSpan.FromMilliseconds(100));

    var err = new SentinelError.ThreatDetected(
        DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "t"),
        SentinelAction.Alert,
        new SessionId("sess-1"));

    await sink.SendAsync(err, default);
    Assert.Equal(1, inner.CallCount);

    await Task.Delay(150);

    await sink.SendAsync(err, default);
    Assert.Equal(2, inner.CallCount);  // second alert passes through after idle expiry
}

[Fact]
public async Task Sweep_RemovesStaleEntries_OverTime()
{
    var inner = new RecordingSink();
    var sink = new DeduplicatingAlertSink(inner, window: null, sessionIdleTimeout: TimeSpan.FromMilliseconds(50));

    // Seed 300 distinct (detector, session) pairs
    for (var i = 0; i < 300; i++)
    {
        var err = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId($"SEC-{i:000}"), Severity.High, "t"),
            SentinelAction.Alert,
            new SessionId($"sess-{i}"));
        await sink.SendAsync(err, default);
    }

    await Task.Delay(100);

    // Trigger a sweep — write 256 more to land on the bitmask boundary
    for (var i = 0; i < 256; i++)
    {
        var err = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId($"SEC-new-{i}"), Severity.High, "t"),
            SentinelAction.Alert,
            new SessionId($"sess-new-{i}"));
        await sink.SendAsync(err, default);
    }

    // After sweep, re-sending one of the original 300 should pass through (it was evicted)
    var reSent = new SentinelError.ThreatDetected(
        DetectionResult.WithSeverity(new DetectorId("SEC-001"), Severity.High, "t"),
        SentinelAction.Alert,
        new SessionId("sess-1"));

    var beforeCount = inner.CallCount;
    await sink.SendAsync(reSent, default);
    Assert.Equal(beforeCount + 1, inner.CallCount);
}

private sealed class RecordingSink : IAlertSink
{
    private int _callCount;
    public int CallCount => _callCount;
    public ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        Interlocked.Increment(ref _callCount);
        return ValueTask.CompletedTask;
    }
}
```

If a `RecordingSink` already exists in the test file, don't duplicate it — reuse. Check the file first.

### Step 2: Run to verify failure

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "SessionScoped_AfterIdleTimeout|Sweep_RemovesStaleEntries" 2>&1 | tail -10
```

Expected: build error — the 3-parameter constructor doesn't exist.

### Step 3: Update `DeduplicatingAlertSink`

In `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs`, replace the full file with:

```csharp
using System.Collections.Concurrent;
using System.Diagnostics;

namespace AI.Sentinel.Alerts;

/// <summary>Alert sink decorator that suppresses repeated alerts for the same detector and session.</summary>
/// <remarks>
/// <para>Session-scoped by default (same detector never re-alerts in the same session).
/// Set <paramref name="window"/> to re-alert after the window expires.</para>
/// <para>The suppression dictionary is lazily swept every 256 writes. Entries whose
/// expiry has passed are removed, bounding memory growth.</para>
/// </remarks>
public sealed class DeduplicatingAlertSink(
    IAlertSink inner,
    TimeSpan? window = null,
    TimeSpan? sessionIdleTimeout = null) : IAlertSink
{
    private readonly TimeSpan _sessionIdleTimeout = sessionIdleTimeout ?? TimeSpan.FromHours(1);
    private readonly ConcurrentDictionary<(string DetectorId, string SessionId), DateTimeOffset> _seen = new();
    private int _writeCount;

    public ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        // PipelineFailure errors always pass through — no session context to key on.
        if (error is not SentinelError.ThreatDetected t)
            return inner.SendAsync(error, ct);

        var detectorId = t.Result.DetectorId.ToString();
        var sessionId = t.Session.ToString();
        var key = (detectorId, sessionId);
        var now = DateTimeOffset.UtcNow;
        var expiry = window is null ? now + _sessionIdleTimeout : now + window.Value;

        var shouldSend = false;
        _seen.AddOrUpdate(
            key,
            _ => { shouldSend = true; return expiry; },
            (_, existing) =>
            {
                if (existing <= now) { shouldSend = true; return expiry; }
                return existing;
            });

        if (!shouldSend)
        {
            SentinelMetrics.AlertsSuppressed.Add(1, new TagList { { "detector", detectorId } });
            return ValueTask.CompletedTask;
        }

        SweepIfNeeded(now);
        return inner.SendAsync(error, ct);
    }

    private void SweepIfNeeded(DateTimeOffset now)
    {
        if ((Interlocked.Increment(ref _writeCount) & 255) != 0) return;
        foreach (var kvp in _seen)
            if (kvp.Value <= now)
                _seen.TryRemove(kvp);
    }
}
```

### Step 4: Update DI wiring

In `src/AI.Sentinel/ServiceCollectionExtensions.cs`, change line 25:

From:
```csharp
            return new DeduplicatingAlertSink(new AlertSinkInstrumented(raw), opts.AlertDeduplicationWindow);
```

To:
```csharp
            return new DeduplicatingAlertSink(
                new AlertSinkInstrumented(raw),
                opts.AlertDeduplicationWindow,
                opts.SessionIdleTimeout);
```

### Step 5: Build and run all tests

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -5
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: new tests pass, all existing tests still pass.

### Step 6: Commit

```bash
git add src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs src/AI.Sentinel/ServiceCollectionExtensions.cs tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs
git commit -m "feat: add lazy sweep to DeduplicatingAlertSink"
```

---

## Task 4: Add `_rateLimiters` eviction to `SentinelPipeline`

Wrap `RateLimiter` with a `LastUsedMs` timestamp in `RateLimiterEntry`. Sweep idle limiters every 256 writes.

**Files:**
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`
- Modify: `tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs`

### Step 1: Write the failing test

Add to `tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs` (inside the class, after the last test):

```csharp
[Fact]
public async Task IdleSession_LimiterEvicted_BurstRestored()
{
    var opts = new SentinelOptions
    {
        MaxCallsPerSecond = 1,
        BurstSize = 1,
        SessionIdleTimeout = TimeSpan.FromMilliseconds(50)
    };
    var pipeline = new DetectionPipeline([], null);
    var audit = new RingBufferAuditStore(100);
    var engine = new InterventionEngine(opts, null);
    var sentinel = new SentinelPipeline(new NoOpChatClient(), pipeline, audit, engine, opts);

    var optsA = new ChatOptions { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = "session-A" } };
    var optsB = new ChatOptions { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = "session-B" } };

    // Exhaust session-A's burst
    _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, default);
    var exhausted = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, default);
    Assert.IsType<SentinelError.RateLimitExceeded>(exhausted.Error);

    // Wait past the idle timeout
    await Task.Delay(100);

    // Trigger a sweep — 256 calls on a different session, each with a unique key so they don't share limiters
    for (var i = 0; i < 256; i++)
    {
        var sweepOpts = new ChatOptions { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = $"sweep-{i}" } };
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], sweepOpts, default);
    }

    // Session-A's entry should be evicted; next call gets a fresh limiter with full burst
    var restored = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, default);
    Assert.True(restored.IsSuccess);
}
```

Note: `NoOpChatClient` is already defined as a private nested class in this test file — reuse it.

### Step 2: Run to verify failure

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "IdleSession_LimiterEvicted" 2>&1 | tail -10
```

Expected: FAIL — the limiter currently never evicts, so the next call on session-A is still rate-limited.

### Step 3: Update `SentinelPipeline`

In `src/AI.Sentinel/SentinelPipeline.cs`, replace line 31:

```csharp
    private readonly ConcurrentDictionary<string, RateLimiter> _rateLimiters = new(StringComparer.Ordinal);
```

With:

```csharp
    private readonly ConcurrentDictionary<string, RateLimiterEntry> _rateLimiters = new(StringComparer.Ordinal);
    private int _rateLimiterWriteCount;

    private sealed class RateLimiterEntry(RateLimiter limiter)
    {
        public RateLimiter Limiter { get; } = limiter;
        public long LastUsedMs = Environment.TickCount64;
    }
```

Replace the existing `CheckRateLimit` method (lines 186–200):

```csharp
    private SentinelError? CheckRateLimit(ChatOptions? chatOptions)
    {
        if (options.MaxCallsPerSecond is not int maxRps) return null;

        var sessionKey = chatOptions?.AdditionalProperties
            ?.GetValueOrDefault("sentinel.session_id") as string ?? "__global__";
        var burst = options.BurstSize ?? maxRps;
        var entry = _rateLimiters.GetOrAdd(sessionKey,
            _ => new RateLimiterEntry(new RateLimiter(maxRps, burst, RateLimitScope.Instance)));
        entry.LastUsedMs = Environment.TickCount64;

        SweepIdleLimiters();

        if (entry.Limiter.TryAcquire()) return null;

        SentinelMetrics.RateLimited.Add(1, new TagList { { "session", sessionKey } });
        return new SentinelError.RateLimitExceeded(sessionKey);
    }

    private void SweepIdleLimiters()
    {
        if ((Interlocked.Increment(ref _rateLimiterWriteCount) & 255) != 0) return;
        var idleThreshold = Environment.TickCount64 - (long)options.SessionIdleTimeout.TotalMilliseconds;
        foreach (var kvp in _rateLimiters)
            if (kvp.Value.LastUsedMs < idleThreshold)
                _rateLimiters.TryRemove(kvp);
    }
```

### Step 4: Build and run all tests

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -5
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: new test passes, all existing tests still pass.

### Step 5: Commit

```bash
git add src/AI.Sentinel/SentinelPipeline.cs tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs
git commit -m "feat: add lazy sweep to SentinelPipeline rate limiter dictionary"
```

---

## Task 5: Smoke test for `SentinelMetrics` + BACKLOG cleanup

**Files:**
- New: `tests/AI.Sentinel.Tests/Telemetry/SentinelMetricsTests.cs`
- Modify: `docs/BACKLOG.md`

### Step 1: Write the smoke test

Create `tests/AI.Sentinel.Tests/Telemetry/SentinelMetricsTests.cs`:

```csharp
using Xunit;

namespace AI.Sentinel.Tests.Telemetry;

public class SentinelMetricsTests
{
    [Fact]
    public void Meter_Name_IsAiSentinel()
    {
        Assert.Equal("ai.sentinel", AI.Sentinel.SentinelMetrics.Meter.Name);
    }

    [Fact]
    public void Counters_AreReachable()
    {
        // Smoke test: these should not throw when accessed via the internals-visible-to
        Assert.NotNull(AI.Sentinel.SentinelMetrics.Threats);
        Assert.NotNull(AI.Sentinel.SentinelMetrics.RateLimited);
        Assert.NotNull(AI.Sentinel.SentinelMetrics.AlertsSuppressed);
    }
}
```

Note: `SentinelMetrics` is `internal`, and the test project should already have `InternalsVisibleTo` configured from the OTel feature. Verify by grepping for `InternalsVisibleTo` in `src/AI.Sentinel`. If absent, add `[assembly: InternalsVisibleTo("AI.Sentinel.Tests")]` to `AssemblyAttributes.cs`.

### Step 2: Update BACKLOG

In `docs/BACKLOG.md`, remove these three rows from the Architecture / Integration section:

- `Centralize Meter singleton into SentinelMetrics`
- `Add eviction to DeduplicatingAlertSink._seen`
- `Add eviction to SentinelPipeline._rateLimiters`

### Step 3: Run full suite

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: all tests pass.

### Step 4: Commit

```bash
git add tests/AI.Sentinel.Tests/Telemetry/SentinelMetricsTests.cs docs/BACKLOG.md
git commit -m "test: smoke test SentinelMetrics, clean backlog"
```
