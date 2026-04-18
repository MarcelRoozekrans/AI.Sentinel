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

    [Fact] public async Task Query_MinSeverity_FiltersLower()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        await store.AppendAsync(new AuditEntry("1", DateTimeOffset.UtcNow, "h1", null, Severity.Low,  "OPS-01", "low"),      CancellationToken.None);
        await store.AppendAsync(new AuditEntry("2", DateTimeOffset.UtcNow, "h2", null, Severity.High, "SEC-01", "high"),     CancellationToken.None);
        await store.AppendAsync(new AuditEntry("3", DateTimeOffset.UtcNow, "h3", null, Severity.None, "OPS-02", "none"),     CancellationToken.None);
        await store.AppendAsync(new AuditEntry("4", DateTimeOffset.UtcNow, "h4", null, Severity.Critical, "SEC-02", "crit"), CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(MinSeverity: Severity.High), CancellationToken.None))
            results.Add(e);

        Assert.Equal(2, results.Count);
        Assert.All(results, e => Assert.True(e.Severity >= Severity.High));
    }

    [Fact] public async Task Query_DateRange_FiltersOutsideWindow()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        var now = DateTimeOffset.UtcNow;
        await store.AppendAsync(new AuditEntry("1", now.AddHours(-2), "h1", null, Severity.High, "SEC-01", "old"),    CancellationToken.None);
        await store.AppendAsync(new AuditEntry("2", now,              "h2", null, Severity.High, "SEC-01", "now"),    CancellationToken.None);
        await store.AppendAsync(new AuditEntry("3", now.AddHours(+2), "h3", null, Severity.High, "SEC-01", "future"), CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(
            new AuditQuery(From: now.AddMinutes(-30), To: now.AddMinutes(30)), CancellationToken.None))
            results.Add(e);

        Assert.Single(results);
        Assert.Equal("h2", results[0].Hash);
    }
}
