using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class AdversarialUnicodeDetector : IDetector
{
    private static readonly DetectorId _id = new("SEC-24");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    private static bool IsSuspicious(char c) =>
        c is '\u200b' or '\u200c' or '\u200d' or '\ufeff' or '\u2060'
        || (c >= '\u202a' && c <= '\u202e')
        || (c >= '\u2066' && c <= '\u2069');

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var count = 0;
        // Tool calls and results count: hidden characters in retrieved content are a classic smuggling route.
        foreach (var message in ctx.Messages)
        {
            foreach (var c in SentinelContext.MessageText(message))
                if (IsSuspicious(c))
                    count++;
        }

        if (count == 0) return ValueTask.FromResult(_clean);

        var severity = count > 2 ? Severity.High : Severity.Medium;
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity,
            $"Adversarial Unicode: {count} suspicious character(s) detected"));
    }
}
