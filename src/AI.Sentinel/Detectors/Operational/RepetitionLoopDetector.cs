using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class RepetitionLoopDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-02");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int maxRepeat = 0;

#if NET9_0_OR_GREATER
        foreach (var range in text.AsSpan().SplitAny(new ReadOnlySpan<char>(['.', '!', '?'])))
        {
            var sentence = text[range].Trim();
            if (sentence.Length <= 5) continue;

            var count = counts.TryGetValue(sentence, out var c) ? c + 1 : 1;
            counts[sentence] = count;
            if (count > maxRepeat) maxRepeat = count;
        }
#else
        var parts = text.Split(['.', '!', '?'], StringSplitOptions.None);
        foreach (var part in parts)
        {
            var sentence = part.Trim();
            if (sentence.Length <= 5) continue;

            var count = counts.TryGetValue(sentence, out var c) ? c + 1 : 1;
            counts[sentence] = count;
            if (count > maxRepeat) maxRepeat = count;
        }
#endif

        if (maxRepeat >= 3)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Sentence repeated {maxRepeat}x — possible repetition loop"));
        return ValueTask.FromResult(_clean);
    }
}
