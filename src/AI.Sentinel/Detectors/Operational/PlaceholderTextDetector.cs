using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed partial class PlaceholderTextDetector : IDetector
{
    public DetectorId Id => new("OPS-07");
    public DetectorCategory Category => DetectorCategory.Operational;

    [GeneratedRegex(@"\b(TODO|FIXME|PLACEHOLDER|Lorem\s+ipsum|YOUR_[A-Z_]+)\b", RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PlaceholderPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
        var match = PlaceholderPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(Id, Severity.Low, $"Placeholder text: '{match.Value}'")
            : DetectionResult.Clean(Id));
    }
}
