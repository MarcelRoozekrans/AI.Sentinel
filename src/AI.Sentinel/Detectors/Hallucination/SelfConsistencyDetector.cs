using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Hallucination;

public sealed partial class SelfConsistencyDetector : ILlmEscalatingDetector
{
    public DetectorId Id => new("HAL-05");
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(@"\b(?<digits>\d[\d,]*)\s*(?:million|billion|thousand)?\b", RegexOptions.ExplicitCapture | RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NumberPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
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
                return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Low,
                    $"Numeric inconsistency: ratio={max / min:F1}x"));
        }
        return ValueTask.FromResult(DetectionResult.Clean(Id));
    }
}
