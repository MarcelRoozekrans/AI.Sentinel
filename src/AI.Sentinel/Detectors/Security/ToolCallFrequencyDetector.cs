using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ToolCallFrequencyDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("SEC-19");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    /// <inheritdoc />
    public string ReviewCriterion =>
        "An unusually large number of tool results in one batch, which may signal an automated sweep or data exfiltration. A burst of calls a task needs, such as a bulk lookup the user asked for, is not a hit.";

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var count = ctx.Messages.Count(m => m.Role == ChatRole.Tool);
        return count switch
        {
            > 20 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"{count} tool calls in one batch — possible automated exfiltration")),
            > 10 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"{count} tool calls in one batch — anomalous spike")),
            > 5 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"{count} tool calls in one batch — elevated frequency")),
            _ => ValueTask.FromResult(_clean),
        };
    }
}
