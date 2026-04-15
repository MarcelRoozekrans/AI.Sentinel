using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed class BlankResponseDetector : IDetector
{
    public DetectorId Id => new("OPS-01");
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join("", ctx.Messages.Select(m => m.Text ?? "")).Trim();
        if (text.Length == 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Medium, "Blank or whitespace-only response"));
        if (text.Length < 10)
            return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Low, "Suspiciously short response"));
        return ValueTask.FromResult(DetectionResult.Clean(Id));
    }
}
