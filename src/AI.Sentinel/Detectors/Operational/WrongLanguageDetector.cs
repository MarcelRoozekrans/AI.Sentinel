using System.Text.RegularExpressions;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class WrongLanguageDetector : IDetector
{
    private static readonly DetectorId _id = new("OPS-15");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    [GeneratedRegex(@"[A-Za-z]",
        RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex LatinCharPattern();

    [GeneratedRegex(@"[\u4e00-\u9fff\u0600-\u06ff\u0400-\u04ff\u0900-\u097f\u0590-\u05ff]",
        RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex NonLatinScriptPattern();

    private static (double latinRatio, double nonLatinRatio) GetScriptRatios(string text)
    {
        if (text.Length == 0) return (0, 0);
        var latinCount = LatinCharPattern().Count(text);
        var nonLatinCount = NonLatinScriptPattern().Count(text);
        var total = (double)(latinCount + nonLatinCount);
        if (total == 0) return (0, 0);
        return (latinCount / total, nonLatinCount / total);
    }

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        string? lastUserText = null;
        string? lastAssistantText = null;

        foreach (var message in ctx.Messages)
        {
            if (message.Role == ChatRole.User)
                lastUserText = message.Text ?? string.Empty;
            else if (message.Role == ChatRole.Assistant)
                lastAssistantText = message.Text ?? string.Empty;
        }

        if (lastUserText is null || lastAssistantText is null)
            return ValueTask.FromResult(_clean);

        if (lastUserText.Length < 20 || lastAssistantText.Length < 20)
            return ValueTask.FromResult(_clean);

        var (userLatin, userNonLatin) = GetScriptRatios(lastUserText);
        var (assistantLatin, assistantNonLatin) = GetScriptRatios(lastAssistantText);

        // User is predominantly Latin but assistant is predominantly non-Latin
        if (userLatin > 0.70 && assistantNonLatin > 0.40)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                "Response language differs from user message language"));

        // User is predominantly non-Latin but assistant is predominantly Latin
        if (userNonLatin > 0.70 && assistantLatin > 0.40)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                "Response language differs from user message language"));

        return ValueTask.FromResult(_clean);
    }
}
