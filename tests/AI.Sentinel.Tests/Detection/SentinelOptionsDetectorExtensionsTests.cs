using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class SentinelOptionsDetectorExtensionsTests
{
    [Fact]
    public void AddDetector_RegistersAsSingleton()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AddDetector<TestDetector>());

        var descriptor = services.Single(d =>
            d.ServiceType == typeof(IDetector) &&
            d.ImplementationType == typeof(TestDetector));
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
    }

    [Fact]
    public void AddDetector_DetectorIsResolvable()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AddDetector<TestDetector>());
        var sp = services.BuildServiceProvider();
        var detectors = sp.GetServices<IDetector>().ToList();

        Assert.Contains(detectors, d => d is TestDetector);
    }

    [Fact]
    public void AddDetector_Factory_UsedForConstruction()
    {
        var captured = new TestDetector();
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AddDetector(_ => captured));
        var sp = services.BuildServiceProvider();
        var resolved = sp.GetServices<IDetector>().OfType<TestDetector>().Single();

        Assert.Same(captured, resolved);
    }

    [Fact]
    public void AddDetector_MultipleCustomDetectors_AllRegistered()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts =>
        {
            opts.AddDetector<TestDetector>();
            opts.AddDetector<AnotherTestDetector>();
        });
        var sp = services.BuildServiceProvider();
        var detectors = sp.GetServices<IDetector>().ToList();

        Assert.Contains(detectors, d => d is TestDetector);
        Assert.Contains(detectors, d => d is AnotherTestDetector);
    }

    [Fact]
    public void AddDetector_AlongsideOfficialDetectors_BothRegistered()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AddDetector<TestDetector>());
        var sp = services.BuildServiceProvider();
        var detectors = sp.GetServices<IDetector>().ToList();

        Assert.True(detectors.Count > 1, "Expected user detector + official detectors registered together");
        Assert.Contains(detectors, d => d is TestDetector);
    }

    private sealed class TestDetector : IDetector
    {
        private static readonly DetectorId _id = new("TEST-01");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(_id));
    }

    private sealed class AnotherTestDetector : IDetector
    {
        private static readonly DetectorId _id = new("TEST-02");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(_id));
    }
}
