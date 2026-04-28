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

        // Wait briefly for the background reader
        await Task.Delay(200);

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
        await Task.Delay(400);

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
        await Task.Delay(150);
        await buf.SendAsync([MakeEntry("e2")], default); // second — must still ship
        await Task.Delay(150);

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
}
