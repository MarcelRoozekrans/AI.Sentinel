using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class BufferingAuditForwarderTests
{
    private static AuditEntry MakeEntry(string id = "e1") =>
        new(id, DateTimeOffset.UtcNow, "h", null, Severity.Low, "T-01", "test");

    [Fact]
    public async Task SizeThreshold_FlushesBatch()
    {
        var inner = new RecordingForwarder();
        await using var buf = new BufferingAuditForwarder<RecordingForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 3, MaxFlushInterval = TimeSpan.FromSeconds(60) });

        for (var i = 0; i < 3; i++)
        {
            await buf.SendAsync([MakeEntry($"e{i}")], default);
        }

        // Bounded poll for the background reader (CI is slower than fixed delays assume).
        await WaitUntilAsync(() => inner.Batches.Count > 0);

        Assert.Single(inner.Batches);
        Assert.Equal(3, inner.Batches[0].Count);
    }

    [Fact]
    public async Task IntervalThreshold_FlushesBatch()
    {
        var inner = new RecordingForwarder();
        await using var buf = new BufferingAuditForwarder<RecordingForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1000, MaxFlushInterval = TimeSpan.FromMilliseconds(150) });

        await buf.SendAsync([MakeEntry()], default);
        // Flush interval is 150ms — poll up to 5s for the interval-driven flush to land.
        await WaitUntilAsync(() => inner.Batches.Count > 0);

        Assert.Single(inner.Batches);
        Assert.Single(inner.Batches[0]);
    }

    [Fact]
    public async Task ChannelOverflow_DropsAndIncrementsCounter()
    {
        var inner = new BlockingForwarder(); // never completes — channel fills up
        await using var buf = new BufferingAuditForwarder<BlockingForwarder>(inner,
            new BufferingAuditForwarderOptions
            {
                MaxBatchSize = 1,
                ChannelCapacity = 2,
                MaxFlushInterval = TimeSpan.FromSeconds(60),
            });

        // Push enough to overflow (2 capacity + 1 reader holding + extras)
        for (var i = 0; i < 20; i++)
        {
            await buf.SendAsync([MakeEntry($"e{i}")], default);
        }

        Assert.True(buf.DroppedCount > 0, "Expected drops once channel filled");
    }

    [Fact]
    public async Task DisposeAsync_FlushesPendingBatch()
    {
        var inner = new RecordingForwarder();
        var buf = new BufferingAuditForwarder<RecordingForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1000, MaxFlushInterval = TimeSpan.FromSeconds(60) });

        await buf.SendAsync([MakeEntry()], default);
        await buf.DisposeAsync();

        Assert.Single(inner.Batches);
    }

    [Fact]
    public async Task InnerThrows_ExceptionSwallowed_KeepsRunning()
    {
        var inner = new ThrowOnceForwarder();
        await using var buf = new BufferingAuditForwarder<ThrowOnceForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1, MaxFlushInterval = TimeSpan.FromMilliseconds(50) });

        await buf.SendAsync([MakeEntry("e1")], default); // first batch — inner throws
        await WaitUntilAsync(() => inner.Calls >= 1);    // wait for the throw to be processed
        await buf.SendAsync([MakeEntry("e2")], default); // second — must still ship
        await WaitUntilAsync(() => inner.SuccessfulSends >= 1);

        Assert.Equal(1, inner.SuccessfulSends);
    }

    private sealed class RecordingForwarder : IAuditForwarder
    {
        public List<IReadOnlyList<AuditEntry>> Batches { get; } = new();
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            Batches.Add(batch);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class BlockingForwarder : IAuditForwarder
    {
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
            => new(Task.Delay(Timeout.Infinite, ct));
    }

    private sealed class ThrowOnceForwarder : IAuditForwarder
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public int SuccessfulSends { get; private set; }
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                throw new InvalidOperationException("first call boom");
            }
            SuccessfulSends++;
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Polls <paramref name="condition"/> until true or timeout. Replaces fixed Task.Delay
    /// waits that flake on slower CI runners.
    /// </summary>
    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 5_000, int pollMs = 25)
    {
        var deadline = Environment.TickCount + timeoutMs;
        while (!condition())
        {
            if (Environment.TickCount > deadline) return;
            await Task.Delay(pollMs).ConfigureAwait(false);
        }
    }
}
