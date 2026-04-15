using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Audit;

public class DetectionPipelineTests
{
    private static SentinelContext FakeContext() => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, "hello") },
        new List<AuditEntry>());

    [Fact] public async Task Pipeline_AllClean_ScoreIsZero()
    {
        var detectors = new IDetector[]
        {
            new FakeDetector("SEC-01", Severity.None),
            new FakeDetector("OPS-01", Severity.None),
        };
        var pipeline = new DetectionPipeline(detectors, escalationClient: null);
        var result = await pipeline.RunAsync(FakeContext(), CancellationToken.None);
        Assert.Equal(0, result.Score.Value);
        Assert.True(result.IsClean);
    }

    [Fact] public async Task Pipeline_OneHigh_ScoreReflectsSeverity()
    {
        var detectors = new IDetector[]
        {
            new FakeDetector("SEC-01", Severity.High),
            new FakeDetector("OPS-01", Severity.None),
        };
        var pipeline = new DetectionPipeline(detectors, escalationClient: null);
        var result = await pipeline.RunAsync(FakeContext(), CancellationToken.None);
        Assert.True(result.Score.Value > 0);
        Assert.False(result.IsClean);
        Assert.Contains(result.Detections, d => d.Severity == Severity.High);
    }

    [Fact] public async Task Pipeline_MaxSeverity_IsHighestDetection()
    {
        var detectors = new IDetector[]
        {
            new FakeDetector("SEC-01", Severity.Medium),
            new FakeDetector("SEC-02", Severity.Critical),
        };
        var pipeline = new DetectionPipeline(detectors, escalationClient: null);
        var result = await pipeline.RunAsync(FakeContext(), CancellationToken.None);
        Assert.Equal(Severity.Critical, result.MaxSeverity);
    }

    // Helpers
    private sealed class FakeDetector(string id, Severity severity) : IDetector
    {
        public DetectorId Id => new(id);
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(severity == Severity.None
                ? DetectionResult.Clean(Id)
                : DetectionResult.WithSeverity(Id, severity, "fake"));
    }
}
