using Xunit;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests.Audit;

public class RingBufferAuditStoreTests
{
    [Fact] public async Task Append_And_Query_Returns_Entry()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        var entry = new AuditEntry(Guid.NewGuid().ToString(), DateTimeOffset.UtcNow,
            "hash1", null, Severity.High, "SEC-01", "test");
        await store.AppendAsync(entry, CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
            results.Add(e);

        Assert.Single(results);
        Assert.Equal("hash1", results[0].Hash);
    }

    [Fact] public async Task RingBuffer_Wraps_At_Capacity()
    {
        var store = new RingBufferAuditStore(capacity: 3);
        for (int i = 0; i < 5; i++)
            await store.AppendAsync(new AuditEntry(i.ToString(System.Globalization.CultureInfo.InvariantCulture), DateTimeOffset.UtcNow,
                $"hash{i}", null, Severity.None, "OPS-01", $"msg{i}"), CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
            results.Add(e);

        Assert.Equal(3, results.Count);
    }
}
