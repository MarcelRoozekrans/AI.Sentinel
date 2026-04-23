using BenchmarkDotNet.Attributes;
using AI.Sentinel.Benchmarks.Harness;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Benchmarks;

[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("E2E")]
public class E2EBenchmarks
{
    [Params("empty", "security", "all")]
    public string DetectorSet { get; set; } = "empty";

    private SentinelChatClient _sentinel = null!;
    private RingBufferAuditStore _auditStore = null!;

    [GlobalSetup]
    public void Setup()
    {
        var pipeline = DetectorSet switch
        {
            "security" => PipelineFactory.SecurityOnly(),
            "all"      => PipelineFactory.All(),
            _          => PipelineFactory.Empty(),
        };

        var options            = SentinelOptionsFactory.AllPassThrough();
        _auditStore            = new RingBufferAuditStore();
        var interventionEngine = new InterventionEngine(options, mediator: null);

        _sentinel = new SentinelChatClient(
            NoOpChatClient.Instance,
            pipeline,
            _auditStore,
            interventionEngine,
            options);
    }

    [GlobalCleanup]
    public void Cleanup() => _auditStore.Dispose();

    [Benchmark(Baseline = true, Description = "GetResponseAsync / clean short")]
    public Task<ChatResponse> GetResponse_CleanShort() =>
        _sentinel.GetResponseAsync(MessageFactory.CleanShort, cancellationToken: CancellationToken.None);

    [Benchmark(Description = "GetResponseAsync / clean long (10 turns)")]
    public Task<ChatResponse> GetResponse_CleanLong() =>
        _sentinel.GetResponseAsync(MessageFactory.CleanLong, cancellationToken: CancellationToken.None);

    [Benchmark(Description = "GetResponseAsync / malicious")]
    public Task<ChatResponse> GetResponse_Malicious() =>
        _sentinel.GetResponseAsync(MessageFactory.Malicious, cancellationToken: CancellationToken.None);

    [Benchmark(Description = "GetStreamingResponseAsync / clean short")]
    public async Task<int> GetStreamingResponse_CleanShort()
    {
        // Measures the buffer-then-scan overhead of the streaming pipeline:
        // we always consume the full IAsyncEnumerable so the response scan fires.
        var count = 0;
        await foreach (var _ in _sentinel.GetStreamingResponseAsync(
            MessageFactory.CleanShort, cancellationToken: CancellationToken.None).ConfigureAwait(false))
        {
            count++;
        }
        return count;
    }

    [Benchmark(Description = "GetStreamingResponseAsync / clean long (10 turns)")]
    public async Task<int> GetStreamingResponse_CleanLong()
    {
        var count = 0;
        await foreach (var _ in _sentinel.GetStreamingResponseAsync(
            MessageFactory.CleanLong, cancellationToken: CancellationToken.None).ConfigureAwait(false))
        {
            count++;
        }
        return count;
    }
}
