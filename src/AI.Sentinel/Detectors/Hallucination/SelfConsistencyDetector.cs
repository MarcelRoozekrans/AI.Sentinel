using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class SelfConsistencyDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("HAL-02");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(@"\b(?<digits>\d[\d,]*)\s*(?:million|billion|thousand)?\b", RegexOptions.ExplicitCapture | RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NumberPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var numbers = NumberPattern().Matches(text)
            .Select(m => double.TryParse(m.Groups["digits"].Value.Replace(",", ""), System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : (double?)null)
            .Where(n => n.HasValue)
            .Select(n => n!.Value)
            .ToList();

        if (numbers.Count >= 2)
        {
            var max = numbers.Max();
            var min = numbers.Min();
            if (max > 0 && min > 0 && max / min > 10)
                return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                    $"Numeric inconsistency: ratio={max / min:F1}x"));
        }
        return ValueTask.FromResult(_clean);
    }
}
