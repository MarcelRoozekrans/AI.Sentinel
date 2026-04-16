using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed class BlankResponseDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-01");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join("", ctx.Messages.Select(m => m.Text ?? "")).Trim();
        if (text.Length == 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium, "Blank or whitespace-only response"));
        if (text.Length < 10)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low, "Suspiciously short response"));
        return ValueTask.FromResult(_clean);
    }
}
