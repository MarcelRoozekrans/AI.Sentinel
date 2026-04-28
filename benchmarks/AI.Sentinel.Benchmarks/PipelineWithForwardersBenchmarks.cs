using BenchmarkDotNet.Attributes;
using AI.Sentinel.Audit;
using AI.Sentinel.Benchmarks.Harness;
using AI.Sentinel.Intervention;

namespace AI.Sentinel.Benchmarks;

/// <summary>
/// Measures <see cref="SentinelPipeline.GetResponseResultAsync"/> cost as a
/// function of registered <see cref="IAuditForwarder"/> count. Every successful
/// audit append fans out via <c>Task.Run</c> to every forwarder fire-and-forget,
/// so per-entry overhead scales with forwarder count even when the forwarder
/// itself is a no-op.
///
/// The post-ship audit-forwarders v1 review flagged this as a Tier-1 silent-regression
/// path: <c>SentinelPipelineBenchmarks</c> always ran with zero forwarders, so the
/// fan-out cost was invisible to the benchmark suite.
///
/// Forwarder counts (0, 1, 3, 5) cover: no-forwarder baseline, single forwarder,
/// realistic multi-sink prod (NDJSON + buffering SIEM + buffering OTel), and a
/// stress-style upper bound.
/// </summary>
[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("SentinelPipeline", "AuditForwarders")]
public class PipelineWithForwardersBenchmarks
{
    [Params(0, 1, 3, 5)]
    public int ForwarderCount { get; set; }

    private SentinelPipeline _pipeline = null!;
    private RingBufferAuditStore _auditStore = null!;

    [GlobalSetup]
    public void Setup()
    {
        var options            = SentinelOptionsFactory.AllPassThrough();
        _auditStore            = new RingBufferAuditStore();
        var interventionEngine = new InterventionEngine(options, mediator: null);

        var forwarders = new IAuditForwarder[ForwarderCount];
        for (int i = 0; i < ForwarderCount; i++)
        {
            forwarders[i] = new MockAuditForwarder();
        }

        _pipeline = new SentinelPipeline(
            NoOpChatClient.Instance,
            PipelineFactory.SecurityOnly(),
            _auditStore,
            interventionEngine,
            options,
            alertSink: null,
            forwarders: forwarders);
    }

    [GlobalCleanup]
    public void Cleanup() => _auditStore.Dispose();

    /// <summary>Two-pass full path: prompt scan + response scan, each appending an
    /// audit entry that fans out to every registered forwarder.</summary>
    [Benchmark(Description = "GetResponseResultAsync / clean (two audit appends, fan out per forwarder)")]
    public async ValueTask Full_Clean() =>
        await _pipeline.GetResponseResultAsync(
            MessageFactory.CleanShort, chatOptions: null, CancellationToken.None);

    /// <summary>Prompt-blocked path: scan trips on prompt, single audit append fans
    /// out to every registered forwarder.</summary>
    [Benchmark(Description = "GetResponseResultAsync / malicious (one audit append, fan out per forwarder)")]
    public async ValueTask Full_Malicious() =>
        await _pipeline.GetResponseResultAsync(
            MessageFactory.Malicious, chatOptions: null, CancellationToken.None);
}
