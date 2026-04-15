using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class ToolPoisoningDetector : IDetector
{
    public DetectorId Id => new("SEC-03");
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(?i)(call\s+tool\s+with|invoke\s+function|execute\s+command|" +
        @"tool_name\s*[=:]\s*|function_call\s*[=:]\s*|<tool_call>|<function_calls>)",
        RegexOptions.Compiled)]
    private static partial Regex ToolPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var userText = string.Join(" ",
            ctx.Messages.Where(m => m.Role != ChatRole.System).Select(m => m.Text ?? ""));
        var match = ToolPattern().Match(userText);
        if (!match.Success) return ValueTask.FromResult(DetectionResult.Clean(Id));
        return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.High,
            $"Possible tool-call injection: '{match.Value}'"));
    }
}
