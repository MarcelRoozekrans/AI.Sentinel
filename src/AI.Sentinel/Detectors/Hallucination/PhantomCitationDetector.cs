using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Hallucination;

public sealed partial class PhantomCitationDetector : ILlmEscalatingDetector
{
    public DetectorId Id => new("HAL-01");
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(
        @"(?i)(arxiv:[89]\d{3}\.\d{4,}|doi:10\.9{3,}/|" +
        @"https?://[a-z0-9\-]+\.(nonexistent|fake|invalid|example)\.[a-z]{2,})",
        RegexOptions.Compiled)]
    private static partial Regex PhantomPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
        var match = PhantomPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(Id, Severity.Medium, $"Suspicious citation: '{match.Value}'")
            : DetectionResult.Clean(Id));
    }
}
