using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class PipelineDetectorConfigTests
{
    private sealed class CountingDetector(Severity severity, string id = "COUNT-01") : IDetector
    {
        public int InvocationCount { get; private set; }
        private readonly DetectorId _id = new(id);
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            InvocationCount++;
            return ValueTask.FromResult(severity == Severity.None
                ? DetectionResult.Clean(_id)
                : DetectionResult.WithSeverity(_id, severity, "stub"));
        }
    }

    private static SentinelContext NewContext()
    {
        return new SentinelContext(
            new AgentId("user"),
            new AgentId("assistant"),
            SessionId.New(),
            Messages: [],
            History: []);
    }

    [Fact]
    public async Task Configure_Enabled_False_DetectorIsNotInvoked()
    {
        var detector = new CountingDetector(Severity.High, "DIS-01");
        var opts = new SentinelOptions();
        opts.Configure<CountingDetector>(c => c.Enabled = false);

        var pipeline = new DetectionPipeline(
            new IDetector[] { detector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        Assert.Equal(0, detector.InvocationCount);
        Assert.Empty(result.Detections);
    }

    [Fact]
    public async Task Configure_Enabled_True_DetectorRuns()
    {
        var detector = new CountingDetector(Severity.High);
        var opts = new SentinelOptions();
        opts.Configure<CountingDetector>(c => c.Enabled = true);  // explicit, default

        var pipeline = new DetectionPipeline(
            new IDetector[] { detector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        Assert.Equal(1, detector.InvocationCount);
        Assert.Single(result.Detections);
        Assert.Equal(Severity.High, result.Detections[0].Severity);
    }
}
