using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed partial class PlaceholderTextDetector : IDetector
{
    private static readonly DetectorId _id = new("OPS-07");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    [GeneratedRegex(@"\b(TODO|FIXME|PLACEHOLDER|Lorem\s+ipsum|YOUR_[A-Z_]+)\b", RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PlaceholderPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = PlaceholderPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(_id, Severity.Low, $"Placeholder text: '{match.Value}'")
            : _clean);
    }
}
