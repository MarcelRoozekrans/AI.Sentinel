using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed class RepetitionLoopDetector : IDetector
{
    public DetectorId Id => new("OPS-02");
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
        var sentences = text.Split(['.', '!', '?'], StringSplitOptions.RemoveEmptyEntries)
                            .Select(s => s.Trim().ToLowerInvariant())
                            .Where(s => s.Length > 5)
                            .ToList();
        if (sentences.Count == 0) return ValueTask.FromResult(DetectionResult.Clean(Id));
        var maxRepeat = sentences.GroupBy(s => s, StringComparer.Ordinal).Max(g => g.Count());
        if (maxRepeat >= 3)
            return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Medium,
                $"Sentence repeated {maxRepeat}x — possible repetition loop"));
        return ValueTask.FromResult(DetectionResult.Clean(Id));
    }
}
