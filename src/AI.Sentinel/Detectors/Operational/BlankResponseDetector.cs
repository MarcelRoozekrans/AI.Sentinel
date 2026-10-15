using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class BlankResponseDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-01");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        // A reply that calls a tool or returns an image is not blank, even without text.
        if (HasNonTextContent(ctx.Messages))
            return ValueTask.FromResult(_clean);

        var text = string.Join("", ctx.Messages.Select(m => m.Text ?? "")).Trim();
        if (text.Length == 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium, "Blank or whitespace-only response"));
        if (text.Length < 10)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low, "Suspiciously short response"));
        return ValueTask.FromResult(_clean);
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
