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

    [Fact]
    public async Task Configure_SeverityFloor_ElevatesFiringResult()
    {
        var detector = new CountingDetector(Severity.Low, "FLR-01");
        var opts = new SentinelOptions();
        opts.Configure<CountingDetector>(c => c.SeverityFloor = Severity.High);

        var pipeline = new DetectionPipeline(
            new IDetector[] { detector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        Assert.Single(result.Detections);
        Assert.Equal(Severity.High, result.Detections[0].Severity);
        Assert.Equal("FLR-01", result.Detections[0].DetectorId.Value, StringComparer.Ordinal);
        Assert.Equal("stub", result.Detections[0].Reason, StringComparer.Ordinal);
    }

    [Fact]
    public async Task Configure_SeverityFloor_LeavesCleanUntouched()
    {
        var detector = new CountingDetector(Severity.None, "CLN-01");
        var opts = new SentinelOptions();
        opts.Configure<CountingDetector>(c => c.SeverityFloor = Severity.Critical);

        var pipeline = new DetectionPipeline(
            new IDetector[] { detector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        Assert.Empty(result.Detections);  // Clean stays Clean — no fabricated finding
    }

    [Fact]
    public async Task Configure_SeverityCap_DowngradesFiringResult()
    {
        var detector = new CountingDetector(Severity.Critical, "CAP-01");
        var opts = new SentinelOptions();
        opts.Configure<CountingDetector>(c => c.SeverityCap = Severity.Low);

        var pipeline = new DetectionPipeline(
            new IDetector[] { detector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        Assert.Single(result.Detections);
        Assert.Equal(Severity.Low, result.Detections[0].Severity);
    }

    [Fact]
    public async Task Configure_SeverityCap_LeavesCleanUntouched()
    {
        var detector = new CountingDetector(Severity.None);
        var opts = new SentinelOptions();
        opts.Configure<CountingDetector>(c => c.SeverityCap = Severity.High);

        var pipeline = new DetectionPipeline(
            new IDetector[] { detector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        Assert.Empty(result.Detections);
    }

    [Fact]
    public async Task Configure_FloorAndCap_BothApply()
    {
        // lowDetector fires Low; Floor=Medium → elevated to Medium. Cap=High doesn't kick in.
        var lowDetector = new CountingDetector(Severity.Low, "BOTH-LOW");
        // critDetector fires Critical; Cap=High → downgraded to High. Floor=Medium doesn't kick in.
        var critDetector = new CountingDetector(Severity.Critical, "BOTH-CRIT");

        var opts = new SentinelOptions();
        opts.Configure<CountingDetector>(c =>
        {
            c.SeverityFloor = Severity.Medium;
            c.SeverityCap = Severity.High;
        });

        var pipeline = new DetectionPipeline(
            new IDetector[] { lowDetector, critDetector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        var bothLow = result.Detections.First(d => string.Equals(d.DetectorId.Value, "BOTH-LOW", StringComparison.Ordinal));
        var bothCrit = result.Detections.First(d => string.Equals(d.DetectorId.Value, "BOTH-CRIT", StringComparison.Ordinal));
        Assert.Equal(Severity.Medium, bothLow.Severity);
        Assert.Equal(Severity.High, bothCrit.Severity);
    }

    [Fact]
    public async Task Configure_UnknownDetectorType_SilentNoOp()
    {
        // Configure references a type that's never registered as a detector.
        // The pipeline should ignore it — no throw, no effect on actually-registered detectors.
        var detector = new CountingDetector(Severity.High, "REAL-01");
        var opts = new SentinelOptions();
        opts.Configure<UnregisteredDetectorType>(c => c.SeverityCap = Severity.Low);

        var pipeline = new DetectionPipeline(
            new IDetector[] { detector },
            opts.GetDetectorConfigurations(),
            escalationClient: null,
            logger: null);

        var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

        Assert.Single(result.Detections);
        Assert.Equal(Severity.High, result.Detections[0].Severity);  // unchanged
    }

    private sealed class UnregisteredDetectorType : IDetector
    {
        private static readonly DetectorId _id = new("UNREG-01");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(_id));
    }
}
