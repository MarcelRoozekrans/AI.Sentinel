using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class PhantomCitationDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("HAL-01");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(
        @"(arxiv:[89]\d{3}\.\d{4,}|doi:10\.9{3,}/|" +
        @"https?://[a-z0-9\-]+\.(?:nonexistent|fake|invalid|example)\.[a-z]{2,})",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PhantomPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = PhantomPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(_id, Severity.Medium, $"Suspicious citation: '{match.Value}'")
            : _clean);
    }
}
