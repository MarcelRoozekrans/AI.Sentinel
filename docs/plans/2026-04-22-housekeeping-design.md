# Housekeeping: Meter Centralization + Unbounded Dictionary Eviction Design

**Goal:** Consolidate scattered `Meter` declarations into `SentinelMetrics`, and stop the `_seen` and `_rateLimiters` dictionaries from growing unbounded by adding lazy time-based eviction with a single `SessionIdleTimeout` option.

**Architecture:** New `internal static class SentinelMetrics` owns the shared `Meter("ai.sentinel")` and every hand-written counter. `DeduplicatingAlertSink._seen` and `SentinelPipeline._rateLimiters` stay as `ConcurrentDictionary` (zero-alloc hot path) but gain a lazy sweep that runs every 256 writes to remove entries idle beyond `SessionIdleTimeout`.

**Tech Stack:** `System.Diagnostics.Metrics.Meter`, `ConcurrentDictionary`, `Interlocked`, `Environment.TickCount64`.

---

## Architecture

Three additive, no-breaking-change components:

1. **`SentinelMetrics` static class** — single `Meter` + all counters
2. **`DeduplicatingAlertSink` sweep** — lazy eviction on write
3. **`SentinelPipeline._rateLimiters` sweep** — lazy eviction wrapping `RateLimiter` with last-used timestamp

One new configuration option: `SentinelOptions.SessionIdleTimeout` (default 1 hour).

---

## 1. Meter centralization

New file `src/AI.Sentinel/SentinelMetrics.cs`:

```csharp
using System.Diagnostics.Metrics;

namespace AI.Sentinel;

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

`SentinelPipeline` and `DeduplicatingAlertSink` reference `SentinelMetrics.Meter` / `SentinelMetrics.*Counter` instead of constructing their own `Meter` instances.

**Unchanged:**
- Source-generator-emitted counters from ZeroAlloc.Telemetry (`sentinel.scans`, `sentinel.scan.ms`, `audit.*`, `alert.sends`) stay in the generated proxy code.
- `SentinelPipeline._activitySource` stays — used only there.

---

## 2. `_seen` eviction (DeduplicatingAlertSink)

`_seen` keeps its `ConcurrentDictionary<(string DetectorId, string SessionId), DateTimeOffset>` shape (zero-alloc value-tuple key).

**Behavior change:** when `window` is null (session-scoped dedup), entries now use `now + sessionIdleTimeout` as expiry instead of `DateTimeOffset.MaxValue`. If an entry goes stale (no alerts for that detector+session within the idle timeout), it's cleaned up on the next sweep.

```csharp
private readonly ConcurrentDictionary<(string, string), DateTimeOffset> _seen = new();
private int _writeCount;

public ValueTask SendAsync(SentinelError error, CancellationToken ct)
{
    if (error is not SentinelError.ThreatDetected t)
        return inner.SendAsync(error, ct);

    var detectorId = t.Result.DetectorId.ToString();
    var sessionId = t.Session.ToString();
    var key = (detectorId, sessionId);
    var now = DateTimeOffset.UtcNow;
    var expiry = window is null ? now + sessionIdleTimeout : now + window.Value;

    var shouldSend = false;
    _seen.AddOrUpdate(key,
        _ => { shouldSend = true; return expiry; },
        (_, existing) =>
        {
            if (existing <= now) { shouldSend = true; return expiry; }
            return existing;
        });

    if (!shouldSend)
    {
        SentinelMetrics.AlertsSuppressed.Add(1, new TagList { ["detector"] = detectorId });
        return ValueTask.CompletedTask;
    }

    SweepIfNeeded(now);
    return inner.SendAsync(error, ct);
}

private void SweepIfNeeded(DateTimeOffset now)
{
    if ((Interlocked.Increment(ref _writeCount) & 255) != 0) return;
    foreach (var kvp in _seen)
        if (kvp.Value <= now) _seen.TryRemove(kvp);
}
```

**Sweep cadence:** every 256 writes — bitmask check, no timer, no background thread.

Constructor signature gains `sessionIdleTimeout`:

```csharp
public sealed class DeduplicatingAlertSink(
    IAlertSink inner,
    TimeSpan? window = null,
    TimeSpan? sessionIdleTimeout = null) : IAlertSink
{
    private readonly TimeSpan sessionIdleTimeout = sessionIdleTimeout ?? TimeSpan.FromHours(1);
    // ...
}
```

---

## 3. `_rateLimiters` eviction (SentinelPipeline)

Wrap `RateLimiter` with a last-used timestamp.

```csharp
private readonly ConcurrentDictionary<string, RateLimiterEntry> _rateLimiters =
    new(StringComparer.Ordinal);
private int _rateLimiterWriteCount;

private sealed class RateLimiterEntry(RateLimiter limiter)
{
    public RateLimiter Limiter { get; } = limiter;
    public long LastUsedMs = Environment.TickCount64;
}

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

    SentinelMetrics.RateLimited.Add(1, new TagList { ["session"] = sessionKey });
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

**Design notes:**
- `Environment.TickCount64` instead of `DateTimeOffset.UtcNow` — cheaper, no DateTime allocation.
- `LastUsedMs` is a non-atomic write — race is benign. Worst case we evict an entry that gets recreated on the next call, starting fresh.
- The `"__global__"` bucket gets touched on every call, so it never evicts in an active pipeline.
- When an idle session resumes, it gets a fresh RateLimiter with full burst — acceptable tradeoff for bounded memory.

---

## 4. SentinelOptions

```csharp
/// <summary>Inactivity window after which per-session dedup state and rate-limiter
/// buckets are evicted from in-memory dictionaries. Default: 1 hour. Increase for
/// long-lived sessions; decrease for very high-cardinality session keys.</summary>
[GreaterThan(typeof(TimeSpan), "00:00:00")]
public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromHours(1);
```

`SentinelOptionsValidator.Validate` rejects zero/negative:

```csharp
if (opts.SessionIdleTimeout <= TimeSpan.Zero)
    failures.Add(new ValidationFailure
    {
        ErrorMessage = "SessionIdleTimeout must be greater than TimeSpan.Zero",
        ErrorCode    = "GreaterThan"
    });
```

`ServiceCollectionExtensions` threads the value to `DeduplicatingAlertSink`:

```csharp
return new DeduplicatingAlertSink(
    new AlertSinkInstrumented(raw),
    opts.AlertDeduplicationWindow,
    opts.SessionIdleTimeout);
```

---

## Testing

### DeduplicatingAlertSinkTests

| Test | Verifies |
|---|---|
| `SessionScoped_AfterIdleTimeout_AlertPassesThrough` | With `window=null`, idle 100ms + wait 150ms → second alert for same (detector, session) reaches inner |
| `Sweep_RemovesStaleEntries_OverTime` | Fill sink with 300 entries, trigger 256-write sweep, assert expired entries are removed |

### SentinelPipelineRateLimitTests

| Test | Verifies |
|---|---|
| `IdleSession_LimiterEvicted_BurstRestored` | Session-A exhausts burst, wait past `SessionIdleTimeout`, trigger sweep (256 calls on another session), Session-A's next call succeeds again |

### SentinelOptionsTests

| Test | Verifies |
|---|---|
| `SessionIdleTimeout_ZeroOrNegative_IsInvalid` | Validator rejects `TimeSpan.Zero` and negative values |

### SentinelMetricsTests (new file or merged)

| Test | Verifies |
|---|---|
| `Meter_Name_IsAiSentinel` | Smoke test — `SentinelMetrics.Meter.Name == "ai.sentinel"` and counters are reachable |

---

## Files changed

| Action | File |
|---|---|
| New | `src/AI.Sentinel/SentinelMetrics.cs` |
| Modify | `src/AI.Sentinel/SentinelPipeline.cs` — use `SentinelMetrics`, add `RateLimiterEntry` + sweep |
| Modify | `src/AI.Sentinel/Alerts/DeduplicatingAlertSink.cs` — use `SentinelMetrics`, add sweep, add `sessionIdleTimeout` parameter |
| Modify | `src/AI.Sentinel/SentinelOptions.cs` — add `SessionIdleTimeout` |
| Modify | `src/AI.Sentinel/SentinelOptionsValidator.cs` — validate `SessionIdleTimeout` |
| Modify | `src/AI.Sentinel/ServiceCollectionExtensions.cs` — pass `SessionIdleTimeout` to `DeduplicatingAlertSink` |
| Modify | `tests/AI.Sentinel.Tests/Alerts/DeduplicatingAlertSinkTests.cs` — 2 new tests |
| Modify | `tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs` — 1 new test |
| Modify | `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs` — 1 new test |
| New or Modify | `tests/AI.Sentinel.Tests/Telemetry/SentinelMetricsTests.cs` — 1 smoke test |
| Modify | `docs/BACKLOG.md` — remove 3 completed items (Meter centralize + both eviction items) |
