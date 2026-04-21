using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SystemPromptLeakageDetector : IDetector
{
    private static readonly DetectorId _id = new("SEC-20");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);
    private const int WindowSize = 5;

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var systemPrompt = FindSystemPrompt(ctx);
        if (systemPrompt is null) return ValueTask.FromResult(_clean);

        var words = systemPrompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0) return ValueTask.FromResult(_clean);

        var otherText = CollectNonSystemText(ctx);
        if (otherText.Length == 0) return ValueTask.FromResult(_clean);

        var (matchCount, longestMatch) = FindLeakedFragments(words, otherText);

        if (matchCount == 0) return ValueTask.FromResult(_clean);

        var severity = matchCount >= 2 || longestMatch >= 8 ? Severity.High : Severity.Medium;
        var label = severity == Severity.High ? "Significant" : "Possible";
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity,
            $"{label} system prompt leakage: {matchCount} fragment(s) detected"));
    }

    private static string? FindSystemPrompt(SentinelContext ctx)
    {
        for (var i = 0; i < ctx.Messages.Count; i++)
        {
            if (ctx.Messages[i].Role == ChatRole.System && ctx.Messages[i].Text is { Length: > 0 } text)
                return text;
        }
        return null;
    }

    private static string CollectNonSystemText(SentinelContext ctx)
    {
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < ctx.Messages.Count; i++)
        {
            if (ctx.Messages[i].Role != ChatRole.System && ctx.Messages[i].Text is not null)
                sb.Append(ctx.Messages[i].Text).Append(' ');
        }
        return sb.ToString();
    }

    private static (int MatchCount, int LongestMatch) FindLeakedFragments(string[] words, string otherText)
    {
        var windowSize = Math.Min(WindowSize, words.Length);
        var matchCount = 0;
        var longestMatch = 0;

        // Find contiguous matched regions (fragments) using a greedy scan.
        // Each region where consecutive sliding windows match counts as one fragment.
        var i = 0;
        while (i <= words.Length - windowSize)
        {
            var window = string.Join(' ', words[i..(i + windowSize)]);
            if (!otherText.Contains(window, StringComparison.OrdinalIgnoreCase))
            {
                i++;
                continue;
            }

            // Found the start of a matching region — extend to find its length.
            var regionEnd = i + windowSize;
            var next = i + 1;
            while (next <= words.Length - windowSize)
            {
                var nextWindow = string.Join(' ', words[next..(next + windowSize)]);
                if (!otherText.Contains(nextWindow, StringComparison.OrdinalIgnoreCase))
                    break;
                regionEnd = next + windowSize;
                next++;
            }

            matchCount++;
            longestMatch = Math.Max(longestMatch, regionEnd - i);
            i = next; // skip past the contiguous region
        }

        return (matchCount, longestMatch);
    }
}
