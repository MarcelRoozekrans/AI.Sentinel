using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detectors;

/// <summary>Base for detectors whose full rule-based implementation requires LLM escalation.</summary>
public abstract class StubDetector : ILlmEscalatingDetector
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
