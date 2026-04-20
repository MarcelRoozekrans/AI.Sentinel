using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class PromptTemplateLeakageDetector : IDetector
{
    private static readonly DetectorId _id = new("SEC-26");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(\{\{[A-Za-z_]\w*\}\}|<SYSTEM>|<INST>|\[INST\]|<<SYS>>|<\|system\|>|<\|user\|>|\{system_prompt\})",
        RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex TemplatePattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = TemplatePattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(_id, Severity.High,
                $"Prompt template leakage: '{match.Value}'")
            : _clean);
    }
}
