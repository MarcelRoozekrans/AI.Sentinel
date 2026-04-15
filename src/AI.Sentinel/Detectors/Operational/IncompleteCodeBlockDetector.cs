using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed class IncompleteCodeBlockDetector : IDetector
{
    public DetectorId Id => new("OPS-06");
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join("\n", ctx.Messages.Select(m => m.Text ?? ""));
        var opens = text.Split("```").Length - 1;
        if (opens % 2 != 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Medium,
                "Unclosed code block — response may be truncated"));
        return ValueTask.FromResult(DetectionResult.Clean(Id));
    }
}
