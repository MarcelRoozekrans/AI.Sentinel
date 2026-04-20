using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class PromptInjectionDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("SEC-01");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
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
        var text = ctx.TextContent;
        var match = InjectionPattern().Match(text);
        if (!match.Success) return ValueTask.FromResult(_clean);
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Critical,
            $"Prompt injection pattern: '{match.Value}'"));
    }
}
