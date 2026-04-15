using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

public interface IDetector
{
    DetectorId Id { get; }
    DetectorCategory Category { get; }
    ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct);
}
