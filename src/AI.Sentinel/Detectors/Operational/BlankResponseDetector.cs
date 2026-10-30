using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class BlankResponseDetector : IDetector
{
    private static readonly DetectorId _id = new("OPS-01");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        // A reply that calls a tool or returns an image is not blank, even without text.
        if (HasNonTextContent(ctx.Messages))
            return ValueTask.FromResult(_clean);

        var length = TrimmedLength(ctx.Messages, ShortLength);
        if (length == 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium, "Blank or whitespace-only response"));
        if (length < ShortLength)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low, "Suspiciously short response"));
        return ValueTask.FromResult(_clean);
    }

    /// <summary>A response with fewer characters than this, once trimmed, is suspiciously short.</summary>
    private const int ShortLength = 10;

    /// <summary>The length of the messages' texts joined and trimmed, or <paramref name="enough"/> as soon as it is
    /// known to be at least that, so a long history is neither joined nor read to its end.</summary>
    /// <remarks>The trimmed join runs from its first non-white-space character to its last. Each message's first and
    /// last non-white-space characters are found in place, so only a message of white space is read through.</remarks>
    private static long TrimmedLength(IReadOnlyList<ChatMessage> messages, int enough)
    {
        long offset = 0;
        long first = -1;
        long last = -1;
        for (var i = 0; i < messages.Count; i++)
        {
            var text = messages[i].Text ?? string.Empty;
            var start = FirstNonWhiteSpace(text);
            if (start >= 0)
            {
                if (first < 0) first = offset + start;
                last = offset + LastNonWhiteSpace(text);
                if (last - first + 1 >= enough) return enough;
            }

            offset += text.Length;
        }

        return first < 0 ? 0 : last - first + 1;
    }

    private static int FirstNonWhiteSpace(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (!char.IsWhiteSpace(text[i])) return i;
        }
        return -1;
    }

    private static int LastNonWhiteSpace(string text)
    {
        for (var i = text.Length - 1; i >= 0; i--)
        {
            if (!char.IsWhiteSpace(text[i])) return i;
        }
        return -1;
    }

    private static bool HasNonTextContent(IReadOnlyList<ChatMessage> messages)
    {
        for (var i = 0; i < messages.Count; i++)
        {
            foreach (var content in messages[i].Contents)
            {
                if (content is not (TextContent or TextReasoningContent or UsageContent))
                    return true;
            }
        }
        return false;
    }
}
