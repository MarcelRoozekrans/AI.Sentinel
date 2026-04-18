using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detectors.Hallucination;

public sealed partial class GroundlessStatisticDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("HAL-08");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(@"\b\d{1,3}(?:\.\d+)?\s*%\s+(?:of|are|were|have|show)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex StatisticPattern();

    [GeneratedRegex(
        @"\((?:source|ref|citation|according|per|via|from)|\[(?:\d+|source)\]|according\s+to",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex SourcePattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var statisticMatch = StatisticPattern().Match(text);

        if (!statisticMatch.Success)
            return ValueTask.FromResult(_clean);

        var matchIndex = statisticMatch.Index;
        var windowStart = Math.Max(0, matchIndex - 200);
        var windowEnd = Math.Min(text.Length, matchIndex + statisticMatch.Length + 200);
        var window = text[windowStart..windowEnd];

        if (SourcePattern().IsMatch(window))
            return ValueTask.FromResult(_clean);

        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
            "Unsourced statistic: percentage claim without citation"));
    }
}
