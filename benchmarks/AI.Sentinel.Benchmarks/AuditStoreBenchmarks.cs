using BenchmarkDotNet.Attributes;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Benchmarks;

[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("AuditStore")]
public class AuditStoreBenchmarks
{
    private RingBufferAuditStore _store = null!;
    private AuditEntry _entry = default!;

    [GlobalSetup]
    public void Setup()
    {
        _store = new RingBufferAuditStore(capacity: 10_000);
        _entry = new AuditEntry(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow,
            "abc123",
            null,
            Severity.Low,
            "SEC-01",
            "benchmark entry");
    }

    [Benchmark(Baseline = true, Description = "AppendAsync single-threaded")]
    public ValueTask AppendAsync_Sequential() =>
        _store.AppendAsync(_entry, CancellationToken.None);

    [Benchmark(Description = "AppendAsync 8 concurrent")]
    public Task AppendAsync_Concurrent8() =>
        Task.WhenAll(Enumerable.Range(0, 8)
            .Select(_ => _store.AppendAsync(_entry, CancellationToken.None).AsTask()));

    [GlobalCleanup]
    public void Cleanup() => _store.Dispose();
}
