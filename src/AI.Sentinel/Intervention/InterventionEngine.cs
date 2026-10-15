using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Intervention;

public sealed class InterventionEngine(
    SentinelOptions options,
    IMediator? mediator,
    ILogger<InterventionEngine>? logger = null)
{
    public void Apply(
        PipelineResult result,
        SessionId? sessionId = null,
        AgentId? sender = null,
        AgentId? receiver = null)
    {
        if (result.IsClean) return;

        var action = SentinelActionRanking.MostRestrictive(result.Detections.Select(options.EffectiveAction));

        if (mediator is not null && action != SentinelAction.PassThrough)
        {
            var now = DateTimeOffset.UtcNow;
            var sid = sessionId ?? new SessionId("unknown");

            PublishSafe(mediator.Publish(new ThreatDetectedNotification(
                sid,
                sender ?? options.DefaultSenderId,
                receiver ?? options.DefaultReceiverId,
                result,
                now)));

            PublishSafe(mediator.Publish(new InterventionAppliedNotification(
                sid,
                action,
                result.MaxSeverity,
                result.Detections.FirstOrDefault()?.Reason ?? "",
                now)));
        }

        if (action == SentinelAction.Quarantine)
            throw new SentinelException(
                $"AI.Sentinel quarantined message: {result.MaxSeverity} threat detected. " +
                $"Detectors: {string.Join(", ", result.Detections.Select(d => d.DetectorId.Value))}",
                result);
    }

    /// <summary>
    /// Publishes an <see cref="InterventionAppliedNotification"/> with <see cref="SentinelAction.Redact"/> for
    /// the values redacted in one call. It carries counts per entity type only, never a value, and no
    /// <see cref="ThreatDetectedNotification"/> is published: a redaction is not a threat.
    /// </summary>
    /// <param name="sessionId">Session of the call.</param>
    /// <param name="countsByType">Number of redacted occurrences per entity type.</param>
    /// <param name="summary">Counts-only summary, for example <c>Redacted 1 EMAIL</c>.</param>
    public void PublishRedaction(SessionId sessionId, IReadOnlyDictionary<string, int> countsByType, string summary)
    {
        ArgumentNullException.ThrowIfNull(sessionId);
        ArgumentNullException.ThrowIfNull(countsByType);
        if (mediator is null) return;

        PublishSafe(mediator.Publish(new InterventionAppliedNotification(
            sessionId,
            SentinelAction.Redact,
            Severity.None,
            summary,
            DateTimeOffset.UtcNow,
            countsByType)));
    }

    // Fast path: synchronous success — no allocation, return immediately.
    // Sync fault: log inline and return.
    // Async path: attach continuation that logs only on fault (OnlyOnFaulted avoids firing for success).
    private void PublishSafe(ValueTask task)
    {
        if (task.IsCompletedSuccessfully) return;
        if (task.IsFaulted)
        {
            logger?.LogWarning(task.AsTask().Exception, "AI.Sentinel: mediator publish failed");
            return;
        }
        _ = task.AsTask().ContinueWith(
            t => logger?.LogWarning(t.Exception, "AI.Sentinel: mediator publish failed"),
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }
}
