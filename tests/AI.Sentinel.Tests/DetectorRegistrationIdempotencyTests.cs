using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests;

/// <summary>Regression tests for #205 — repeated AddAISentinel calls multiplied the official
/// detector set, so the README's named-pipeline example built a pipeline holding 3x55 detectors.</summary>
public class DetectorRegistrationIdempotencyTests
{
    // Rule-based trigger (SEC-02 CredentialExposureDetector): a synthetic GitHub-PAT-shaped
    // string. Semantic detectors such as SEC-01 no-op without an embedding generator, so they
    // cannot carry a behavioural assertion here.
    private const string FakeLeakedToken = "ghp_" + "abcdefghij0123456789abcdefghij012345";

    private static SentinelContext LeakedCredentialContext() => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, $"here is the token {FakeLeakedToken}") },
        new List<AuditEntry>());

    private static List<string> DuplicateDetectorTypes(IServiceProvider provider) =>
        provider.GetServices<IDetector>()
            .GroupBy(d => d.GetType())
            .Where(g => g.Count() > 1)
            .Select(g => g.Key.Name)
            .ToList();

    [Fact]
    public void AddAISentinel_CalledTwice_DoesNotDuplicateDetectors()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        services.AddAISentinel();

        Assert.Empty(DuplicateDetectorTypes(services.BuildServiceProvider()));
    }

    [Fact]
    public void AddAISentinel_ReadmeNamedPipelineExample_DoesNotDuplicateDetectors()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o => { });
        services.AddAISentinel("strict", o => { });
        services.AddAISentinel("lenient", o => { });

        var provider = services.BuildServiceProvider();
        var detectors = provider.GetServices<IDetector>().ToList();

        Assert.Empty(DuplicateDetectorTypes(provider));
        Assert.Equal(detectors.Select(d => d.GetType()).Distinct().Count(), detectors.Count);
    }

    [Fact]
    public void AddAISentinel_ManyTimes_KeepsTheOfficialSetAtItsFullSize()
    {
        var baseline = BuildOfficialDetectorCount(callCount: 1);

        Assert.Equal(baseline, BuildOfficialDetectorCount(callCount: 2));
        Assert.Equal(baseline, BuildOfficialDetectorCount(callCount: 5));

        static int BuildOfficialDetectorCount(int callCount)
        {
            var services = new ServiceCollection();
            for (var i = 0; i < callCount; i++)
            {
                services.AddAISentinel();
            }

            return services.BuildServiceProvider().GetServices<IDetector>().Count();
        }
    }

    /// <summary>The guard must not over-reach: deduplication covers only the source-generated
    /// official set. Registering the same user detector type twice is a legitimate request
    /// (two instances, different constructor arguments) and must still yield two detectors.</summary>
    [Fact]
    public void AddAISentinel_SameUserDetectorTypeTwice_KeepsBothInstances()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.AddDetector(_ => new ConfigurableTestDetector("CUSTOM-01"));
            o.AddDetector(_ => new ConfigurableTestDetector("CUSTOM-02"));
        });

        var ids = services.BuildServiceProvider().GetServices<IDetector>()
            .OfType<ConfigurableTestDetector>()
            .Select(d => d.Id.Value)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(new[] { "CUSTOM-01", "CUSTOM-02" }, ids, StringComparer.Ordinal);
    }

    /// <summary>README.md documents extracting a shared <c>Action&lt;SentinelOptions&gt;</c> and applying it to
    /// the default pipeline and each named one. When that shared action contains a type-based
    /// <c>AddDetector&lt;T&gt;()</c>, T must still land in the global pool exactly once — two instances of one
    /// type cannot be configured apart, since Configure&lt;T&gt; is keyed by type.</summary>
    [Fact]
    public void AddAISentinel_SharedBaseConfigAcrossPipelines_RegistersUserDetectorTypeOnce()
    {
        Action<SentinelOptions> baseCfg = o => o.AddDetector<SharedBaseConfigDetector>();

        var services = new ServiceCollection();
        services.AddAISentinel(o => baseCfg(o));
        services.AddAISentinel("strict", o => baseCfg(o));
        services.AddAISentinel("lenient", o => baseCfg(o));

        var registered = services.BuildServiceProvider().GetServices<IDetector>()
            .OfType<SharedBaseConfigDetector>()
            .ToList();

        Assert.Single(registered);
    }

    [Fact]
    public async Task SharedBaseConfigDetector_ReportsItsFindingOnce()
    {
        Action<SentinelOptions> baseCfg = o => o.AddDetector<SharedBaseConfigDetector>();

        var services = new ServiceCollection();
        services.AddAISentinel(o => baseCfg(o));
        services.AddAISentinel("strict", o => baseCfg(o));

        var pipeline = services.BuildServiceProvider().GetRequiredService<IDetectionPipeline>();
        var result = await pipeline.RunAsync(LeakedCredentialContext(), TestContext.Current.CancellationToken);

        Assert.Single(result.Detections, d => string.Equals(d.DetectorId.Value, SharedBaseConfigDetector.DetectorIdValue, StringComparison.Ordinal));
    }

    private sealed class SharedBaseConfigDetector : IDetector
    {
        public const string DetectorIdValue = "SHARED-01";
        public DetectorId Id => new(DetectorIdValue);
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Low, "shared-base-config probe"));
    }

    private sealed class ConfigurableTestDetector(string id) : IDetector
    {
        public DetectorId Id => new(id);
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
    }

    [Fact]
    public async Task DefaultPipeline_AfterRepeatedRegistration_ReportsEachThreatOnce()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o => { });
        services.AddAISentinel("strict", o => { });
        services.AddAISentinel("lenient", o => { });

        var pipeline = services.BuildServiceProvider().GetRequiredService<IDetectionPipeline>();
        var result = await pipeline.RunAsync(LeakedCredentialContext(), TestContext.Current.CancellationToken);

        Assert.NotEmpty(result.Detections);
        var repeated = result.Detections
            .GroupBy(d => d.DetectorId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key.Value)
            .ToList();
        Assert.Empty(repeated);
    }

    [Fact]
    public async Task NamedPipeline_AfterRepeatedRegistration_ReportsEachThreatOnce()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o => { });
        services.AddAISentinel("strict", o => { });

        var pipeline = services.BuildServiceProvider()
            .GetRequiredKeyedService<IDetectionPipeline>("strict");
        var result = await pipeline.RunAsync(LeakedCredentialContext(), TestContext.Current.CancellationToken);

        Assert.NotEmpty(result.Detections);
        Assert.Empty(result.Detections
            .GroupBy(d => d.DetectorId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key.Value));
    }
}
