using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

public sealed record PipelineResult(
    ThreatRiskScore Score,
    IReadOnlyList<DetectionResult> Detections)
{
    public bool IsClean => Score.Value == 0;
    public Severity MaxSeverity => Detections.Count == 0
        ? Severity.None
        : Detections.Max(d => d.Severity);
}
