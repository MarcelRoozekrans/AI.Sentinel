using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detectors.Hallucination;

public sealed partial class StaleKnowledgeDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("HAL-06");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(
        @"(as\s+of\s+(?:today|now|currently|this\s+(?:year|month|week))|the\s+(?:current|latest|newest|most\s+recent)\s+(?:version|release|ceo|president|price|rate)|right\s+now\s+the)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex StaleClaimPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = StaleClaimPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(_id, Severity.Low, $"Potentially stale claim: '{match.Value}'")
            : _clean);
    }
}
