using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class SessionHistoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

    private static AuditEntry Entry(string? session, DateTimeOffset at, string detector = "SEC-01",
        Severity severity = Severity.High) =>
        new(Guid.NewGuid().ToString("N"), at, "h", null, severity, detector, "s") { SessionId = session };

    private sealed class FakeStore(IReadOnlyList<AuditEntry> entries) : IAuditStore
    {
        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) => new(entry);

        public async IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query,
            [EnumeratorCancellation] CancellationToken ct)
        {
            foreach (var e in entries) yield return e;
            await Task.CompletedTask;
        }
    }

    private sealed class ThrowingStore(Exception ex) : IAuditStore
    {
        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) => new(entry);

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) =>
            throw (ct.IsCancellationRequested ? new OperationCanceledException(ct) : ex);
    }

    [Fact]
    public async Task ReadAsync_ReturnsOnlyThisSession_OldestFirst()
    {
        var store = new FakeStore([
            Entry("s", Now.AddMinutes(-1)), Entry("other", Now.AddMinutes(-2)),
            Entry(null, Now.AddMinutes(-3)), Entry("s", Now.AddMinutes(-10)),
        ]);

        var result = await SessionHistory.ReadAsync(store, "s", Now, null, CancellationToken.None);

        Assert.Equal(2, result.Count);
        Assert.All(result, e => Assert.Equal("s", e.SessionId));
        Assert.True(result[0].Timestamp < result[1].Timestamp);
    }

    [Fact]
    public async Task ReadAsync_DropsEntriesOlderThan24Hours()
    {
        var old = Entry("s", Now.AddHours(-25));
        var recent = Entry("s", Now.AddHours(-23));
        var result = await SessionHistory.ReadAsync(new FakeStore([old, recent]), "s", Now, null, CancellationToken.None);

        Assert.DoesNotContain(result, e => string.Equals(e.Id, old.Id, StringComparison.Ordinal));
        Assert.Contains(result, e => string.Equals(e.Id, recent.Id, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReadAsync_StoreIgnoresReverse_KeepsNewest50()
    {
        var all = Enumerable.Range(0, 60).Select(i => Entry("s", Now.AddMinutes(-120 + i))).ToList();

        var result = await SessionHistory.ReadAsync(new FakeStore(all), "s", Now, null, CancellationToken.None);

        Assert.Equal(SessionHistory.MaxEntries, result.Count);
        Assert.Equal(all.Skip(10).Select(e => e.Id), result.Select(e => e.Id), StringComparer.Ordinal);
    }

    [Fact]
    public async Task ReadAsync_FutureTimestamp_IsKept()
    {
        var future = Entry("s", Now.AddMinutes(5));
        var result = await SessionHistory.ReadAsync(new FakeStore([future]), "s", Now, null, CancellationToken.None);

        Assert.Contains(result, e => string.Equals(e.Id, future.Id, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReadAsync_StoreThrows_ReturnsEmptyAndReports()
    {
        var messages = new List<string>();
        var result = await SessionHistory.ReadAsync(new ThrowingStore(new InvalidOperationException("boom")),
            "sess-42", Now, messages.Add, CancellationToken.None);

        Assert.Empty(result);
        var message = Assert.Single(messages);
        Assert.Contains("sess-42", message);
    }

    [Fact]
    public async Task ReadAsync_CancelledToken_Throws()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await SessionHistory.ReadAsync(new ThrowingStore(new InvalidOperationException()), "s", Now, null, cts.Token));
    }

    [Fact]
    public async Task CountEarlierHits_CountsOnlyThisDetectorAndSession()
    {
        var store = new FakeStore([
            Entry("s", Now.AddMinutes(-1), "OPS-13"),
            Entry("other", Now.AddMinutes(-2), "OPS-13"),
            Entry("s", Now.AddMinutes(-3), "SEC-01"),
            Entry("s", Now.AddMinutes(-4), "OPS-13", Severity.None),
        ]);

        var count = await SessionHistory.CountEarlierHitsAsync(store, "s", "OPS-13", Now, null, CancellationToken.None);

        Assert.Equal(1, count);
    }

    [Fact]
    public async Task CountEarlierHits_CapsAtThreshold()
    {
        var store = new FakeStore(Enumerable.Range(0, 5).Select(i => Entry("s", Now.AddMinutes(-i), "OPS-13")).ToList());

        var count = await SessionHistory.CountEarlierHitsAsync(store, "s", "OPS-13", Now, null, CancellationToken.None);

        Assert.Equal(SessionHistory.EscalationThreshold, count);
    }

    [Fact]
    public async Task CountEarlierHits_StoreThrows_ReturnsZeroAndReports()
    {
        var messages = new List<string>();
        var count = await SessionHistory.CountEarlierHitsAsync(new ThrowingStore(new InvalidOperationException("boom")),
            "sess-42", "OPS-13", Now, messages.Add, CancellationToken.None);

        Assert.Equal(0, count);
        Assert.Contains("sess-42", Assert.Single(messages));
    }
}
