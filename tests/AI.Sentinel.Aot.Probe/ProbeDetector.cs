using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Aot.Probe;

/// <summary>A do-nothing detector registered by type, so ILC sees the
/// <c>AddDetector&lt;T&gt;</c> path that stores <c>typeof(T)</c> in a DetectorRegistration.</summary>
internal sealed class ProbeDetector : IDetector
{
    private static readonly DetectorId ProbeId = new("PROBE-01");

    public DetectorId Id => ProbeId;

    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
        ValueTask.FromResult(DetectionResult.Clean(ProbeId));
}
