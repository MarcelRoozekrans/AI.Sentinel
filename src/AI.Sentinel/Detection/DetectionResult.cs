using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

public sealed record DetectionResult(
    DetectorId DetectorId,
    Severity Severity,
    string Reason)
{
    public static DetectionResult Clean(DetectorId id) =>
        new(id, Severity.None, string.Empty);

    public static DetectionResult WithSeverity(DetectorId id, Severity severity, string reason) =>
        new(id, severity, reason);

    /// <summary>Per-detector action that replaces the severity-to-action mapping for this detection.
    /// <see cref="SentinelAction.Redact"/> here means redaction was not possible and the severity action applies.</summary>
    public SentinelAction? ActionOverride { get; init; }

    public bool IsClean => Severity == Severity.None;
}
