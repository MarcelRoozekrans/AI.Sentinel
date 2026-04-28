using BenchmarkDotNet.Attributes;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;

namespace AI.Sentinel.Benchmarks;

/// <summary>
/// Measures <see cref="IAuditStore"/> append + query throughput, parametrized
/// across both shipped implementations:
/// <list type="bullet">
///   <item><description><see cref="RingBufferAuditStore"/> — in-memory, allocation-bounded baseline.</description></item>
///   <item><description><see cref="SqliteAuditStore"/> — persistent, durable, ~100x slower per append.</description></item>
/// </list>
/// Coverage is intentional: the two are wire-compatible behind <see cref="IAuditStore"/>,
/// and a user swapping in SQLite without realizing the cost gap is a real Tier-1 risk
/// the post-ship audit-forwarders v1 review flagged.
/// </summary>
[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("AuditStore")]
public class AuditStoreBenchmarks
{
    public enum AuditStoreType
    {
        RingBuffer,
        Sqlite,
    }

    [Params(AuditStoreType.RingBuffer, AuditStoreType.Sqlite)]
    public AuditStoreType StoreType { get; set; }

    private IAuditStore _store = null!;
    private string? _tempDbPath;
    private AuditEntry _entry = default!;

    [GlobalSetup]
    public void Setup()
    {
        _entry = new AuditEntry(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow,
            "abc123",
            null,
            Severity.Low,
            "SEC-01",
            "benchmark entry");

        if (StoreType == AuditStoreType.RingBuffer)
        {
            _store = new RingBufferAuditStore(capacity: 10_000);
        }
        else
        {
            _tempDbPath = Path.Combine(Path.GetTempPath(), $"sentinel-bench-{Guid.NewGuid():N}.db");
            _store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _tempDbPath });
        }
    }

    [Benchmark(Baseline = true, Description = "AppendAsync single-threaded")]
    public ValueTask AppendAsync_Sequential() =>
        _store.AppendAsync(_entry, CancellationToken.None);

    [Benchmark(Description = "AppendAsync 8 concurrent")]
    public Task AppendAsync_Concurrent8()
    {
        var tasks = new Task[8];
        for (int i = 0; i < 8; i++)
        {
            tasks[i] = _store.AppendAsync(_entry, CancellationToken.None).AsTask();
        }
        return Task.WhenAll(tasks);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        switch (_store)
        {
            case IAsyncDisposable a:
                a.DisposeAsync().AsTask().GetAwaiter().GetResult();
                break;
            case IDisposable d:
                d.Dispose();
                break;
        }

        if (_tempDbPath is not null)
        {
            try { File.Delete(_tempDbPath); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}
