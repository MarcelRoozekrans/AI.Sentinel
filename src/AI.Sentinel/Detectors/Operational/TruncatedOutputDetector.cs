using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class TruncatedOutputDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-09");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent.TrimEnd();
        if (text.Length == 0) return ValueTask.FromResult(_clean);

        var fenceCount = CountOccurrences(text, "```");
        if (fenceCount % 2 != 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                "Unclosed code fence — response may be truncated"));

        if (text.EndsWith("...", StringComparison.Ordinal))
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                "Response ends with ellipsis — possible truncation"));

        var last = text[^1];
        if (char.IsLower(last) || last == ',')
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                "Response ends mid-sentence — likely truncated"));

        return ValueTask.FromResult(_clean);
    }

    private static int CountOccurrences(string text, string value)
    {
        int count = 0, index = 0;
        while ((index = text.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }
        return count;
    }
}
