using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class UnboundedConsumptionDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-11");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var responseLen = ctx.Messages
            .Where(m => m.Role == ChatRole.Assistant)
            .Sum(m => (m.Text ?? "").Length);
        var promptLen = ctx.Messages
            .Where(m => m.Role == ChatRole.User)
            .Sum(m => (m.Text ?? "").Length);

        if (responseLen == 0) return ValueTask.FromResult(_clean);
        if (promptLen == 0) return ValueTask.FromResult(_clean);

        var ratio = (double)responseLen / promptLen;

        if (responseLen > 50_000 || ratio > 100)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"Response {responseLen:N0} chars ({ratio:F0}× prompt) — possible resource exhaustion"));
        if (responseLen > 15_000 || ratio > 40)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Response {responseLen:N0} chars ({ratio:F0}× prompt) — abnormally large"));
        if (responseLen > 5_000 || ratio > 15)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"Response {responseLen:N0} chars ({ratio:F0}× prompt) — unusually large"));

        return ValueTask.FromResult(_clean);
    }
}
