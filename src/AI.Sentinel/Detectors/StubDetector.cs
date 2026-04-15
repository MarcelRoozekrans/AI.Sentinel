using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors;

/// <summary>Base for detectors whose full rule-based implementation requires LLM escalation.</summary>
public abstract class StubDetector(string id, DetectorCategory category) : ILlmEscalatingDetector
{
    public DetectorId Id => new(id);
    public DetectorCategory Category => category;
    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
        ValueTask.FromResult(DetectionResult.Clean(Id));
}
