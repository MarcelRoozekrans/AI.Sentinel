using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class CodeInjectionDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("SEC-25");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(@"```[\s\S]*?```", RegexOptions.ExplicitCapture | RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CodeFencePattern();

    [GeneratedRegex(
        @"(union\s+select|drop\s+table|insert\s+into.*values|xp_cmdshell|exec\s*\(|" +
        @"\$\(.*\)|` .*`|\beval\s*\(|;\s*rm\s+-rf|&&\s*curl|wget\s+http|" +
        @"(\.\./){2,}|%2e%2e%2f)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex InjectionPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        foreach (var message in ctx.Messages)
        {
            if (message.Role != ChatRole.Assistant) continue;
            var text = message.Text;
            if (text is null) continue;

            foreach (Match fence in CodeFencePattern().Matches(text))
            {
                var block = fence.Value;
                var match = InjectionPattern().Match(block);
                if (match.Success)
                    return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                        $"Code injection in generated code: '{match.Value[..Math.Min(30, match.Value.Length)]}'"));
            }
        }

        return ValueTask.FromResult(_clean);
    }
}
