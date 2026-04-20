using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
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
            new PipelineResult(SeverityToScore(t.Result.Severity), [t.Result])),
        PipelineFailure f => new InvalidOperationException(f.Message, f.Inner),
        _ => new InvalidOperationException("Unknown SentinelError")
    };

    private static ThreatRiskScore SeverityToScore(Severity severity) => new(severity switch
    {
        Severity.Critical => 100,
        Severity.High     => 70,
        Severity.Medium   => 40,
        Severity.Low      => 15,
        _                 => 0
    });
}
