using System.Text.RegularExpressions;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class IntraSessionContradictionDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("HAL-07");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(@"\b\d[\d,]*(?:\.\d+)?\b",
        RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex NumberPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var allNumbers = new List<double>();

        foreach (var message in ctx.Messages)
        {
            if (message.Role != ChatRole.Assistant)
                continue;

            var text = message.Text ?? string.Empty;
            foreach (Match m in NumberPattern().Matches(text))
            {
                if (double.TryParse(m.Value.Replace(",", ""),
                        System.Globalization.NumberStyles.Any,
                        System.Globalization.CultureInfo.InvariantCulture,
                        out var n))
                {
                    allNumbers.Add(n);
                }
            }
        }

        if (allNumbers.Count >= 2)
        {
            var max = allNumbers.Max();
            var min = allNumbers.Min();
            if (max > 0 && min > 0 && max / min > 10)
                return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                    $"Cross-turn numeric inconsistency: {max:G4} vs {min:G4} across assistant messages"));
        }

        return ValueTask.FromResult(_clean);
    }
}
