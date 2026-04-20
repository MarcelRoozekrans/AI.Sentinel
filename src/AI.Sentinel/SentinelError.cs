using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;

namespace AI.Sentinel;

public abstract record SentinelError
{
    public sealed record ThreatDetected(DetectionResult Result, SentinelAction Action) : SentinelError;
    public sealed record PipelineFailure(string Message, Exception? Inner = null) : SentinelError;

    public Exception ToException() => this switch
    {
        ThreatDetected t => new SentinelException(
            $"AI.Sentinel quarantined message: {t.Result.Severity} threat detected by {t.Result.DetectorId}.",
            t.Result),
        PipelineFailure f => new InvalidOperationException(f.Message, f.Inner),
        _ => new InvalidOperationException("Unknown SentinelError")
    };
}
