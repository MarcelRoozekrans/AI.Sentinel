using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;

namespace AI.Sentinel;

/// <summary>Represents an error produced by the AI.Sentinel pipeline.</summary>
public abstract record SentinelError
{
    /// <summary>Indicates a threat was detected and an action was taken.</summary>
    /// <param name="Result">The highest-severity detection that triggered this error.</param>
    /// <param name="Action">The action taken in response to the detection.</param>
    public sealed record ThreatDetected(DetectionResult Result, SentinelAction Action) : SentinelError;

    /// <summary>Indicates the pipeline itself failed with an unhandled exception or internal error.</summary>
    /// <param name="Message">A human-readable description of the failure.</param>
    /// <param name="Inner">The underlying exception that caused the failure, if any.</param>
    public sealed record PipelineFailure(string Message, Exception? Inner = null) : SentinelError;

    /// <summary>Converts this error to a throwable <see cref="Exception"/>.</summary>
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
