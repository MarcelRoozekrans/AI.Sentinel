using System.Collections.Concurrent;
using System.Diagnostics;

namespace AI.Sentinel.Alerts;

/// <summary>Alert sink decorator that suppresses repeated alerts for the same detector and session.</summary>
/// <remarks>
/// <para>Session-scoped by default (same detector never re-alerts in the same session).
/// Set <paramref name="window"/> to re-alert after the window expires.</para>
/// <para>The suppression dictionary is not evicted. In session-scoped mode (window = null), entries accumulate over the lifetime of the singleton proportional to unique (DetectorId, SessionId) pairs seen. This is negligible in typical deployments.</para>
/// </remarks>
public sealed class DeduplicatingAlertSink(IAlertSink inner, TimeSpan? window = null) : IAlertSink
{
    private readonly ConcurrentDictionary<(string DetectorId, string SessionId), DateTimeOffset> _seen = new();

    public ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        // PipelineFailure errors always pass through — no session context to key on.
        if (error is not SentinelError.ThreatDetected t)
            return inner.SendAsync(error, ct);

        var detectorId = t.Result.DetectorId.ToString();
        var sessionId = t.Session.ToString();
        var key = (detectorId, sessionId);
        var now = DateTimeOffset.UtcNow;
        var expiry = window is null ? DateTimeOffset.MaxValue : now + window.Value;

        var shouldSend = false;
        _seen.AddOrUpdate(
            key,
            _ => { shouldSend = true; return expiry; },                      // first occurrence
            (_, existing) =>
            {
                if (existing <= now) { shouldSend = true; return expiry; }   // window expired — reset
                return existing;                                              // still within window
            });

        if (!shouldSend)
        {
            SentinelMetrics.AlertsSuppressed.Add(1, new TagList { { "detector", detectorId } });
            return ValueTask.CompletedTask;
        }

        return inner.SendAsync(error, ct);
    }
}
