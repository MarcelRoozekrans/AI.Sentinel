using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;
using System.Globalization;

namespace AI.Sentinel.Sqlite.Tests;

public sealed class SqliteAuditStoreReverseQueryTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-reverse-{Guid.NewGuid():N}.db"));

    public void Dispose()
    {
        TryDelete(_dbPath);
        TryDelete(_dbPath + "-wal");
        TryDelete(_dbPath + "-shm");
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public async Task QueryWithReverse_AndPageSize_ReturnsMostRecentEntriesNotOldest()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        // Seed 12 entries with monotonically increasing timestamps so we can identify which 10 we get back.
        var baseTime = DateTimeOffset.UtcNow.AddMinutes(-30);
        for (int i = 0; i < 12; i++)
        {
            var entry = new AuditEntry(
                Id:           $"e{i:D2}",
                Timestamp:    baseTime.AddMinutes(i),
                Hash:         "h",
                PreviousHash: null,
                Severity:     Severity.Medium,
                DetectorId:   "SEC-01",
                Summary:      $"entry {i}",
                PolicyCode:   null,
                SessionId:    null);
            await store.AppendAsync(entry, CancellationToken.None);
        }

        // Without Reverse: would get the OLDEST 10 (e00-e09) — the bug we're fixing.
        // With Reverse: should get the NEWEST 10 (e02-e11).
        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: 10, Reverse: true), CancellationToken.None))
            results.Add(e);

        Assert.Equal(10, results.Count);
        // Reverse=true means newest-first, so results[0] should be e11.
        Assert.Equal("e11", results[0].Id);
        Assert.Equal("e02", results[9].Id);
        // Crucially, the OLDEST entry (e00) should NOT be in the result.
        Assert.DoesNotContain(results, r => string.Equals(r.Id, "e00", StringComparison.Ordinal));
        Assert.DoesNotContain(results, r => string.Equals(r.Id, "e01", StringComparison.Ordinal));
    }
}
