using Xunit;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests.Audit;

public class RingBufferAuditStoreTests
{
    [Fact]
    public async Task Append_And_Query_Returns_Entry()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        var entry = new AuditEntry(Guid.NewGuid().ToString(), DateTimeOffset.UtcNow,
            "hash1", null, Severity.High, "SEC-01", "test");
        await store.AppendAsync(entry, CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
            results.Add(e);

        Assert.Single(results);
        Assert.Equal(entry.Id, results[0].Id);
    }

    [Fact]
    public async Task RingBuffer_Wraps_At_Capacity()
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

    [Fact]
    public async Task Query_MinSeverity_FiltersLower()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        await store.AppendAsync(new AuditEntry("1", DateTimeOffset.UtcNow, "h1", null, Severity.Low, "OPS-01", "low"), CancellationToken.None);
        await store.AppendAsync(new AuditEntry("2", DateTimeOffset.UtcNow, "h2", null, Severity.High, "SEC-01", "high"), CancellationToken.None);
        await store.AppendAsync(new AuditEntry("3", DateTimeOffset.UtcNow, "h3", null, Severity.None, "OPS-02", "none"), CancellationToken.None);
        await store.AppendAsync(new AuditEntry("4", DateTimeOffset.UtcNow, "h4", null, Severity.Critical, "SEC-02", "crit"), CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { MinSeverity = Severity.High }, CancellationToken.None))
            results.Add(e);

        Assert.Equal(2, results.Count);
        Assert.All(results, e => Assert.True(e.Severity >= Severity.High));
    }

    [Fact]
    public async Task Query_DateRange_FiltersOutsideWindow()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        var now = DateTimeOffset.UtcNow;
        await store.AppendAsync(new AuditEntry("1", now.AddHours(-2), "h1", null, Severity.High, "SEC-01", "old"), CancellationToken.None);
        await store.AppendAsync(new AuditEntry("2", now, "h2", null, Severity.High, "SEC-01", "now"), CancellationToken.None);
        await store.AppendAsync(new AuditEntry("3", now.AddHours(+2), "h3", null, Severity.High, "SEC-01", "future"), CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(
            new AuditQuery { From = now.AddMinutes(-30), To = now.AddMinutes(30) }, CancellationToken.None))
            results.Add(e);

        Assert.Single(results);
        Assert.Equal("2", results[0].Id);
    }

    private static AuditEntry Unlinked(string id) =>
        new(id, DateTimeOffset.UtcNow, string.Empty, null, Severity.High, "SEC-01", $"summary-{id}");

    private static async Task<List<AuditEntry>> AllAsync(IAuditStore store)
    {
        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, CancellationToken.None))
            results.Add(e);
        return results;
    }

    [Fact]
    public async Task Append_ReturnsTheEntryLinkedToThePreviousOne()
    {
        var store = new RingBufferAuditStore(capacity: 100);

        var first = await store.AppendAsync(Unlinked("e1"), CancellationToken.None);
        var second = await store.AppendAsync(Unlinked("e2"), CancellationToken.None);

        Assert.Null(first.PreviousHash);
        Assert.Equal(first.Hash, second.PreviousHash);
        Assert.Equal(AuditHashChain.ComputeHash(second), second.Hash);
    }

    [Fact]
    public async Task Append_ReplacesHashValuesSuppliedByTheCaller()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        var forged = Unlinked("e1") with { Hash = "forged", PreviousHash = "forged-previous" };

        var stored = await store.AppendAsync(forged, CancellationToken.None);

        Assert.Null(stored.PreviousHash);
        Assert.Equal(AuditHashChain.ComputeHash(stored), stored.Hash);
    }

    [Fact]
    public async Task Query_ReturnsTheEntriesAsStored()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        var stored = await store.AppendAsync(Unlinked("e1"), CancellationToken.None);

        var all = await AllAsync(store);

        Assert.Equal(stored, Assert.Single(all));
    }

    [Fact]
    public async Task ConcurrentAppends_FormOneIntactChain()
    {
        var store = new RingBufferAuditStore(capacity: 1_000);

        await Task.WhenAll(Enumerable.Range(0, 200).Select(i =>
            store.AppendAsync(Unlinked($"e{i}"), CancellationToken.None).AsTask()));

        var result = await AuditHashChain.VerifyAsync(store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, CancellationToken.None), CancellationToken.None);
        Assert.True(result.IsIntact);
        Assert.Equal(200, result.EntriesChecked);
        Assert.Null(result.AnchorHash);
    }

    [Fact]
    public async Task Eviction_LeavesAnIntactChainAnchoredOnTheEvictedEntry()
    {
        var store = new RingBufferAuditStore(capacity: 3);
        var appended = new List<AuditEntry>();
        for (var i = 0; i < 5; i++)
            appended.Add(await store.AppendAsync(Unlinked($"e{i}"), CancellationToken.None));

        var result = await AuditHashChain.VerifyAsync(store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, CancellationToken.None), CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(3, result.EntriesChecked);
        Assert.Equal(appended[1].Hash, result.AnchorHash);
    }

    [Fact]
    public async Task Query_Source_FiltersIgnoringCase()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        await store.AppendAsync(new AuditEntry("1", DateTimeOffset.UtcNow, "h1", null, Severity.Low, "OPS-01", "a") { Source = "mcp" }, CancellationToken.None);
        await store.AppendAsync(new AuditEntry("2", DateTimeOffset.UtcNow, "h2", null, Severity.Low, "OPS-01", "b") { Source = "copilot" }, CancellationToken.None);
        await store.AppendAsync(new AuditEntry("3", DateTimeOffset.UtcNow, "h3", null, Severity.Low, "OPS-01", "c"), CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { Source = "MCP" }, CancellationToken.None))
            results.Add(e);

        Assert.Equal("1", Assert.Single(results).Id);
    }

    [Fact]
    public async Task Query_DetectorIdAndPolicyCode_FilterOrdinally()
    {
        var store = new RingBufferAuditStore(capacity: 100);
        await store.AppendAsync(new AuditEntry("1", DateTimeOffset.UtcNow, "h1", null, Severity.None, "APPROVAL", "a") { PolicyCode = "APPROVED" }, CancellationToken.None);
        await store.AppendAsync(new AuditEntry("2", DateTimeOffset.UtcNow, "h2", null, Severity.None, "APPROVAL", "b") { PolicyCode = "DENIED" }, CancellationToken.None);
        await store.AppendAsync(new AuditEntry("3", DateTimeOffset.UtcNow, "h3", null, Severity.Low, "approval", "c") { PolicyCode = "APPROVED" }, CancellationToken.None);
        await store.AppendAsync(new AuditEntry("4", DateTimeOffset.UtcNow, "h4", null, Severity.Low, "SEC-01", "d"), CancellationToken.None);

        async Task<string[]> Ids(AuditQuery query)
        {
            var ids = new List<string>();
            await foreach (var e in store.QueryAsync(query, CancellationToken.None)) ids.Add(e.Id);
            return [.. ids];
        }

        Assert.Equal(["1", "2"], await Ids(new AuditQuery { DetectorId = "APPROVAL" }));
        Assert.Equal(["1", "3"], await Ids(new AuditQuery { PolicyCode = "APPROVED" }));
        Assert.Equal(["1"], await Ids(new AuditQuery { DetectorId = "APPROVAL", PolicyCode = "APPROVED" }));
        Assert.Empty(await Ids(new AuditQuery { PolicyCode = "approved" }));
        Assert.Equal(4, (await Ids(new AuditQuery())).Length);
    }

    private static async Task<string[]> QueryIds(RingBufferAuditStore store, AuditQuery query)
    {
        var ids = new List<string>();
        await foreach (var e in store.QueryAsync(query, CancellationToken.None)) ids.Add(e.Id);
        return [.. ids];
    }

    private static async Task<RingBufferAuditStore> FilledStoreAsync()
    {
        var store = new RingBufferAuditStore(1_000);
        for (int i = 1; i <= 1_000; i++)
            await store.AppendAsync(new AuditEntry(i.ToString(System.Globalization.CultureInfo.InvariantCulture),
                DateTimeOffset.UtcNow, $"h{i}", null, Severity.None, "OPS-01", "m")
                { SessionId = i % 100 == 0 ? "s" : "other" }, CancellationToken.None);
        return store;
    }

    [Fact]
    public async Task Query_SessionFilterOnFullBuffer_ReturnsNewestMatchesOnly()
    {
        var store = await FilledStoreAsync();

        var ids = await QueryIds(store, new AuditQuery { SessionId = "s", Reverse = true, PageSize = 3 });

        Assert.Equal(["1000", "900", "800"], ids);
    }

    [Fact]
    public async Task Query_ForwardWithPageSize_ReturnsOldestMatches()
    {
        var store = await FilledStoreAsync();

        var ids = await QueryIds(store, new AuditQuery { SessionId = "s", PageSize = 3 });

        Assert.Equal(["100", "200", "300"], ids);
    }

    [Fact]
    public async Task Query_WrappedBuffer_KeepsOrder()
    {
        var store = new RingBufferAuditStore(capacity: 5);
        for (int i = 1; i <= 8; i++)
            await store.AppendAsync(new AuditEntry(i.ToString(System.Globalization.CultureInfo.InvariantCulture),
                DateTimeOffset.UtcNow, $"h{i}", null, Severity.None, "OPS-01", "m"), CancellationToken.None);

        Assert.Equal(["4", "5", "6", "7", "8"], await QueryIds(store, new AuditQuery()));
        Assert.Equal(["8", "7", "6", "5", "4"], await QueryIds(store, new AuditQuery { Reverse = true }));
    }
}
