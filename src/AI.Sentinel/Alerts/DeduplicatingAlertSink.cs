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
