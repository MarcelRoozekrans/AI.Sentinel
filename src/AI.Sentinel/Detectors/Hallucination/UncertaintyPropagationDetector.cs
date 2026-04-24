using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class UncertaintyPropagationDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("HAL-09");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(
        @"\b(i\s+think|i\s+believe|possibly|probably|might\s+be|it\s+seems|perhaps|not\s+certain)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex HedgingPattern();

    [GeneratedRegex(
        @"\b(the\s+answer\s+is|it\s+is|this\s+means|therefore|in\s+fact|certainly)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AssertionPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var hedging = HedgingPattern().Match(text);
        if (!hedging.Success) return ValueTask.FromResult(_clean);

        if (AssertionPattern().IsMatch(text))
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Uncertainty promoted to assertion (hedging: '{hedging.Value}')"));

        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
            $"Hedged claim: '{hedging.Value}'"));
    }
}
