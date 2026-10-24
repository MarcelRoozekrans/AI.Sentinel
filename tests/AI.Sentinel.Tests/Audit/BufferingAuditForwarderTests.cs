using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class BufferingAuditForwarderTests
{
    private static AuditEntry MakeEntry(string id = "e1") =>
        new(id, DateTimeOffset.UtcNow, "h", null, Severity.Low, "T-01", "test");

    [Fact]
    public async Task SizeThreshold_FlushesBatch()
    {
        var inner = new RecordingAuditForwarder();
        await using var buf = new BufferingAuditForwarder<RecordingAuditForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 3, MaxFlushInterval = TimeSpan.FromMinutes(10) });

        for (var i = 0; i < 3; i++)
        {
            await buf.SendAsync([MakeEntry($"e{i}")], TestContext.Current.CancellationToken);
        }

        // The interval is far beyond the wait bound, so only the size threshold can flush: the reader
        // holds the entries until the third arrives and ships them as one batch, in order.
        await inner.WaitForAsync(3);

        Assert.Equal(3, Assert.Single(inner.Batches).Count);
        Assert.Equal(["e0", "e1", "e2"], inner.Entries.Select(e => e.Id), StringComparer.Ordinal);
    }

    [Fact]
    public async Task IntervalThreshold_FlushesBatch()
    {
        var inner = new RecordingAuditForwarder();
        await using var buf = new BufferingAuditForwarder<RecordingAuditForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1000, MaxFlushInterval = TimeSpan.FromMilliseconds(150) });

        await buf.SendAsync([MakeEntry()], TestContext.Current.CancellationToken);

        // The batch is far below MaxBatchSize and the forwarder is not disposed until after the
        // wait, so only the interval flush can deliver it. The wait bound is a hang detector, not
        // a timing expectation: a loaded machine may run the 150 ms flush late, never not at all.
        await inner.WaitForAsync(1);

        var batch = Assert.Single(inner.Batches);
        Assert.Equal("e1", Assert.Single(batch).Id);
    }

    // A 1 ms interval puts the reader at the interval boundary on every entry, where it used to hold an entry until the
    // next one arrived: CancelAfter dropped the sub-millisecond part, so the timer could fire before the interval had
    // passed, the reader saw "not yet", and its next read had no timeout. On .NET 10, a read cancelled by that timer
    // could also lose the entry.
    [Fact]
    public async Task IntervalThreshold_NearTheBoundary_NeverHoldsAPartialBatch()
    {
        var inner = new RecordingAuditForwarder();
        await using var buf = new BufferingAuditForwarder<RecordingAuditForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1000, MaxFlushInterval = TimeSpan.FromMilliseconds(1) });

        for (var i = 1; i <= 200; i++)
        {
            await buf.SendAsync([MakeEntry($"e{i}")], TestContext.Current.CancellationToken);
            await inner.WaitForAsync(i);
        }
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
            await buf.SendAsync([MakeEntry($"e{i}")], TestContext.Current.CancellationToken);
        }

        Assert.True(buf.DroppedCount > 0, "Expected drops once channel filled");
    }

    [Fact]
    public async Task DisposeAsync_FlushesPendingBatch()
    {
        var inner = new RecordingAuditForwarder();
        var buf = new BufferingAuditForwarder<RecordingAuditForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1000, MaxFlushInterval = TimeSpan.FromMinutes(10) });

        await buf.SendAsync([MakeEntry()], TestContext.Current.CancellationToken);
        await buf.DisposeAsync();

        Assert.Equal("e1", Assert.Single(inner.Entries).Id);
    }

    [Fact]
    public async Task InnerThrows_ExceptionSwallowed_KeepsRunning()
    {
        var inner = new ThrowOnceForwarder();
        await using var buf = new BufferingAuditForwarder<ThrowOnceForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1, MaxFlushInterval = TimeSpan.FromMinutes(10) });

        // MaxBatchSize = 1 puts each entry in its own batch, so e1 is the batch that throws.
        await buf.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);
        await buf.SendAsync([MakeEntry("e2")], TestContext.Current.CancellationToken);
        await inner.Delivered.WaitForAsync(1);

        Assert.Equal("e2", Assert.Single(inner.Delivered.Entries).Id);
    }

    private sealed class BlockingForwarder : IAuditForwarder
    {
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
            => new(Task.Delay(Timeout.Infinite, ct));
    }

    private sealed class ThrowOnceForwarder : IAuditForwarder
    {
        private int _calls;
        public RecordingAuditForwarder Delivered { get; } = new();
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                throw new InvalidOperationException("first call boom");
            }
            return Delivered.SendAsync(batch, ct);
        }
    }
}
