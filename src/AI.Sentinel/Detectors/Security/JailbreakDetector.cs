using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class JailbreakDetector : ILlmEscalatingDetector
{
    public DetectorId Id => new("SEC-13");
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(?i)(DAN\s+mode|jailbreak|no\s+restrictions?|no\s+guidelines?|" +
        @"no\s+(ethical\s+)?constraints?|pretend\s+you\s+have\s+no|" +
        @"you\s+are\s+freed\s+from|unrestricted\s+AI|evil\s+mode)",
        RegexOptions.Compiled)]
    private static partial Regex JailbreakPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
        var match = JailbreakPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(Id, Severity.Critical, $"Jailbreak attempt: '{match.Value}'")
            : DetectionResult.Clean(Id));
    }
}
