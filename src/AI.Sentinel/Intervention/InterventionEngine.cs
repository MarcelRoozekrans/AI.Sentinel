using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Intervention;

public sealed class InterventionEngine(SentinelOptions options, IMediator? mediator)
{
    public void Apply(
        PipelineResult result,
        SessionId? sessionId = null,
        AgentId? sender = null,
        AgentId? receiver = null)
    {
        if (result.IsClean) return;

        var action = options.ActionFor(result.MaxSeverity);

        if (mediator is not null)
        {
            var now = DateTimeOffset.UtcNow;
            var sid = sessionId ?? new SessionId("unknown");
            _ = mediator.Publish(new ThreatDetectedNotification(
                sid,
                sender ?? options.DefaultSenderId,
                receiver ?? options.DefaultReceiverId,
                result,
                now));
            _ = mediator.Publish(new InterventionAppliedNotification(
                sid,
                action,
                result.MaxSeverity,
                result.Detections.FirstOrDefault()?.Reason ?? "",
                now));
        }

        if (action == SentinelAction.Quarantine)
            throw new SentinelException(
                $"AI.Sentinel quarantined message: {result.MaxSeverity} threat detected. " +
                $"Detectors: {string.Join(", ", result.Detections.Select(d => d.DetectorId))}",
                result);
    }
}
