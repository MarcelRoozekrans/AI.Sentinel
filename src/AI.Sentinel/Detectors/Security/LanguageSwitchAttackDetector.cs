using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class LanguageSwitchAttackDetector : IDetector
{
    private static readonly DetectorId _id = new("SEC-27");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    private static bool IsNonLatin(char c) =>
        (c >= '\u4e00' && c <= '\u9fff') ||  // CJK
        (c >= '\u0600' && c <= '\u06ff') ||  // Arabic
        (c >= '\u0400' && c <= '\u04ff') ||  // Cyrillic
        (c >= '\u0900' && c <= '\u097f');    // Devanagari

    private static bool IsLatin(char c) => c >= '\u0041' && c <= '\u024f';

    private static bool IsDominantlyLatin(string text)
    {
        int latin = 0, total = 0;
        foreach (var c in text)
        {
            if (!char.IsLetter(c)) continue;
            total++;
            if (IsLatin(c)) latin++;
        }
        return total == 0 || (double)latin / total >= 0.7;
    }

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        string? userText = null;
        string? assistantText = null;

        foreach (var message in ctx.Messages)
        {
            if (message.Role == ChatRole.User && userText is null)
                userText = message.Text;
            else if (message.Role == ChatRole.Assistant)
                assistantText = message.Text;
        }

        if (userText is null || assistantText is null)
            return ValueTask.FromResult(_clean);

        if (!IsDominantlyLatin(userText))
            return ValueTask.FromResult(_clean);

        int nonLatinCount = 0, totalLetters = 0;
        foreach (var c in assistantText)
        {
            if (!char.IsLetter(c)) continue;
            totalLetters++;
            if (IsNonLatin(c)) nonLatinCount++;
        }

        if (totalLetters > 0 && (double)nonLatinCount / totalLetters > 0.20)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                "Language switch detected: response script differs from user prompt"));

        return ValueTask.FromResult(_clean);
    }
}
