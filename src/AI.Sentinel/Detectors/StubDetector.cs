using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detectors;

/// <summary>Base for a detector that is declared but not implemented: it always returns Clean.</summary>
/// <remarks>
/// Deliberately not <c>ILlmEscalatingDetector</c>. That interface was declared here, implying an
/// EscalationClient would activate these detectors, but <see cref="DetectionPipeline"/> only
/// re-classifies findings already at <see cref="Severity.Medium"/> or above — and a stub produces
/// none. The combination was unreachable, so the promise could never be met by any configuration.
/// Escalation refines a finding; it cannot create one.
/// </remarks>
public abstract class StubDetector : IDetector
{
    private readonly DetectorId _id;
    private readonly DetectionResult _clean;

    protected StubDetector(string id, DetectorCategory category)
    {
        _id    = new DetectorId(id);
        _clean = DetectionResult.Clean(_id);
        Category = category;
    }

    public DetectorId Id => _id;
    public DetectorCategory Category { get; }

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
        ValueTask.FromResult(_clean);
}
