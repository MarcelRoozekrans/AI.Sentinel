using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class SentinelOptionsConfigureExtensionsTests
{
    private sealed class FakeDetector : IDetector
    {
        private static readonly DetectorId _id = new("FAKE-01");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(_id));
    }

    private sealed class OtherFakeDetector : IDetector
    {
        private static readonly DetectorId _id = new("FAKE-02");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(_id));
    }

    [Fact]
    public void Configure_DefaultConfiguration_HasExpectedDefaults()
    {
        var opts = new SentinelOptions();
        opts.Configure<FakeDetector>(_ => { });

        var cfg = opts.GetDetectorConfigurations()[typeof(FakeDetector)];
        Assert.True(cfg.Enabled);
        Assert.Null(cfg.SeverityFloor);
        Assert.Null(cfg.SeverityCap);
    }

    [Fact]
    public void Configure_StoresConfigurationKeyedByType()
    {
        var opts = new SentinelOptions();
        opts.Configure<FakeDetector>(c => c.Enabled = false);
        opts.Configure<OtherFakeDetector>(c => c.SeverityFloor = Severity.High);

        var configs = opts.GetDetectorConfigurations();
        Assert.False(configs[typeof(FakeDetector)].Enabled);
        Assert.Equal(Severity.High, configs[typeof(OtherFakeDetector)].SeverityFloor);
    }

    [Fact]
    public void Configure_MultipleCalls_MergeByMutation()
    {
        var opts = new SentinelOptions();
        opts.Configure<FakeDetector>(c => c.SeverityFloor = Severity.High);
        opts.Configure<FakeDetector>(c => c.SeverityCap = Severity.Critical);

        var cfg = opts.GetDetectorConfigurations()[typeof(FakeDetector)];
        Assert.Equal(Severity.High, cfg.SeverityFloor);
        Assert.Equal(Severity.Critical, cfg.SeverityCap);
    }

    [Fact]
    public void Configure_SameProperty_LastWins()
    {
        var opts = new SentinelOptions();
        opts.Configure<FakeDetector>(c => c.SeverityFloor = Severity.High);
        opts.Configure<FakeDetector>(c => c.SeverityFloor = Severity.Critical);

        var cfg = opts.GetDetectorConfigurations()[typeof(FakeDetector)];
        Assert.Equal(Severity.Critical, cfg.SeverityFloor);
    }

    [Fact]
    public void Configure_FloorGreaterThanCap_ThrowsAtRegistration()
    {
        var opts = new SentinelOptions();

        var ex = Assert.Throws<ArgumentException>(() =>
            opts.Configure<FakeDetector>(c =>
            {
                c.SeverityFloor = Severity.Critical;
                c.SeverityCap = Severity.Low;
            }));

        Assert.Contains("FakeDetector", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Floor", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Cap", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Configure_NullConfigureLambda_ThrowsArgumentNullException()
    {
        var opts = new SentinelOptions();
        Assert.Throws<ArgumentNullException>(() => opts.Configure<FakeDetector>(null!));
    }
}
