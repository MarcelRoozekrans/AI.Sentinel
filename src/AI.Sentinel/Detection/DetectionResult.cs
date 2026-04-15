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

    public bool IsClean => Severity == Severity.None;
}
