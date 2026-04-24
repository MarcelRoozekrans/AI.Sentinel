using BenchmarkDotNet.Attributes;
using AI.Sentinel.Audit;
using AI.Sentinel.Benchmarks.Harness;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Benchmarks;

/// <summary>
/// Measures <see cref="SentinelPipeline"/> directly, isolating the orchestrator
/// overhead (rate limiter, session id, audit store, intervention engine) from
/// the <see cref="SentinelChatClient"/> IChatClient-compat shim.
///
/// Pairs the two-pass <see cref="SentinelPipeline.GetResponseResultAsync"/>
/// with the prompt-only <see cref="SentinelPipeline.ScanMessagesAsync"/> on
/// the same inputs so the hook-adapter fast-path's saving vs the full path
/// is visible in the report.
/// </summary>
[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("SentinelPipeline")]
public class SentinelPipelineBenchmarks
{
    private SentinelPipeline _pipeline = null!;
    private RingBufferAuditStore _auditStore = null!;

    [GlobalSetup]
    public void Setup()
    {
        var options            = SentinelOptionsFactory.AllPassThrough();
        _auditStore            = new RingBufferAuditStore();
        var interventionEngine = new InterventionEngine(options, mediator: null);

        _pipeline = new SentinelPipeline(
            NoOpChatClient.Instance,
            PipelineFactory.SecurityOnly(),
            _auditStore,
            interventionEngine,
            options);
    }

    [GlobalCleanup]
    public void Cleanup() => _auditStore.Dispose();

    [Benchmark(Baseline = true, Description = "GetResponseResultAsync / clean (two-pass)")]
    public async ValueTask Full_Clean() =>
        await _pipeline.GetResponseResultAsync(
            MessageFactory.CleanShort, chatOptions: null, CancellationToken.None);

    [Benchmark(Description = "GetResponseResultAsync / malicious (two-pass, blocks on prompt)")]
    public async ValueTask Full_Malicious() =>
        await _pipeline.GetResponseResultAsync(
            MessageFactory.Malicious, chatOptions: null, CancellationToken.None);

    [Benchmark(Description = "ScanMessagesAsync / clean (prompt-only, hook path)")]
    public ValueTask<SentinelError?> PromptOnly_Clean() =>
        _pipeline.ScanMessagesAsync(
            MessageFactory.CleanShort, chatOptions: null, CancellationToken.None);

    [Benchmark(Description = "ScanMessagesAsync / malicious (prompt-only, hook path)")]
    public ValueTask<SentinelError?> PromptOnly_Malicious() =>
        _pipeline.ScanMessagesAsync(
            MessageFactory.Malicious, chatOptions: null, CancellationToken.None);
}
