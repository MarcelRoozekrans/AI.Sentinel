using BenchmarkDotNet.Attributes;
using AI.Sentinel.Benchmarks.Harness;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Benchmarks;

[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("Pipeline")]
public class PipelineBenchmarks
{
    private DetectionPipeline _empty           = null!;
    private DetectionPipeline _security        = null!;
    private DetectionPipeline _all             = null!;
    private DetectionPipeline _securitySemantic = null!;
    private DetectionPipeline _allSemantic      = null!;

    private SentinelContext _cleanCtx    = null!;
    private SentinelContext _maliciousCtx = null!;

    [GlobalSetup]
    public void Setup()
    {
        _empty    = PipelineFactory.Empty();
        _security = PipelineFactory.SecurityOnly();
        _all      = PipelineFactory.All();

        var semanticOpts  = SentinelOptionsFactory.WithSemanticDetection();
        _securitySemantic = PipelineFactory.SecurityOnly(semanticOpts);
        _allSemantic      = PipelineFactory.All(semanticOpts);

        _cleanCtx     = BuildContext(MessageFactory.CleanShort);
        _maliciousCtx = BuildContext(MessageFactory.Malicious);
    }

    [Benchmark(Baseline = true, Description = "Empty pipeline / clean")]
    public ValueTask<PipelineResult> Empty_Clean() =>
        _empty.RunAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "Security-only / clean")]
    public ValueTask<PipelineResult> SecurityOnly_Clean() =>
        _security.RunAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "Security-only / malicious")]
    public ValueTask<PipelineResult> SecurityOnly_Malicious() =>
        _security.RunAsync(_maliciousCtx, CancellationToken.None);

    [Benchmark(Description = "All detectors / clean")]
    public ValueTask<PipelineResult> All_Clean() =>
        _all.RunAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "All detectors / malicious")]
    public ValueTask<PipelineResult> All_Malicious() =>
        _all.RunAsync(_maliciousCtx, CancellationToken.None);

    [Benchmark(Description = "Security-only / semantic / clean (cache cold)")]
    public ValueTask<PipelineResult> SecurityOnly_Semantic_Clean() =>
        _securitySemantic.RunAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "All detectors / semantic / clean (cache cold)")]
    public ValueTask<PipelineResult> All_Semantic_Clean() =>
        _allSemantic.RunAsync(_cleanCtx, CancellationToken.None);

    private static SentinelContext BuildContext(IReadOnlyList<ChatMessage> msgs) =>
        new(new AgentId("user"), new AgentId("assistant"),
            SessionId.New(), msgs, []);
}
