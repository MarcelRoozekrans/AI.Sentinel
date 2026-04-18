using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class JailbreakDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("SEC-05");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(DAN\s+mode|jailbreak|no\s+restrictions?|no\s+guidelines?|" +
        @"no\s+(ethical\s+)?constraints?|pretend\s+you\s+have\s+no|" +
        @"you\s+are\s+freed\s+from|unrestricted\s+AI|evil\s+mode)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex JailbreakPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = JailbreakPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(_id, Severity.Critical, $"Jailbreak attempt: '{match.Value}'")
            : _clean);
    }
}
