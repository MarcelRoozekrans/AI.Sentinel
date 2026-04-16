using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class PromptInjectionDetector : ILlmEscalatingDetector
{
    public DetectorId Id => new("SEC-01");
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|" +
        @"forget\s+(your\s+)?(previous|prior|all)\s+instructions?|" +
        @"you\s+are\s+now\s+a\s+different|" +
        @"SYSTEM\s*:\s*(you\s+are|ignore)|" +
        @"new\s+persona|pretend\s+you\s+are|act\s+as\s+if|" +
        @"disregard\s+(all\s+)?previous)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex InjectionPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
        var match = InjectionPattern().Match(text);
        if (!match.Success) return ValueTask.FromResult(DetectionResult.Clean(Id));
        return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical,
            $"Prompt injection pattern: '{match.Value}'"));
    }
}
