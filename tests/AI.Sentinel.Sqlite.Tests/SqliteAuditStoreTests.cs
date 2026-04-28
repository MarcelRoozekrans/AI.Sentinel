using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

public sealed class SqliteAuditStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-{Guid.NewGuid():N}.db"));

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

    private static AuditEntry Make(string id, string? prevHash = null, Severity severity = Severity.High, string detectorId = "SEC-01") =>
        new(id, DateTimeOffset.UtcNow, $"h-{id}", prevHash, severity, detectorId, $"summary-{id}");

    [Fact]
    public async Task Append_PersistsToFile_QueryReturnsAfterReopen()
    {
        var entry = Make("e1");

        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            await store.AppendAsync(entry, CancellationToken.None);
        }

        await using (var reopened = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            var results = new List<AuditEntry>();
            await foreach (var e in reopened.QueryAsync(new AuditQuery(), CancellationToken.None))
            {
                results.Add(e);
            }
            Assert.Single(results);
            Assert.Equal("e1", results[0].Id);
            Assert.Equal("h-e1", results[0].Hash);
            Assert.Equal(Severity.High, results[0].Severity);
            Assert.Equal("SEC-01", results[0].DetectorId);
        }
    }

    [Fact]
    public async Task HashChain_PreviousHashLinksToLastEntryOnReopen()
    {
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            await store.AppendAsync(Make("e1"), CancellationToken.None);
        }

        await using (var reopened = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            var lastHash = await reopened.GetLastHashForTestingAsync(CancellationToken.None);
            Assert.Equal("h-e1", lastHash);
        }
    }

    [Fact]
    public async Task Query_FiltersByMinSeverity()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        await store.AppendAsync(Make("e1", severity: Severity.High,     detectorId: "SEC-01"), CancellationToken.None);
        await store.AppendAsync(Make("e2", severity: Severity.Low,      detectorId: "SEC-01"), CancellationToken.None);
        await store.AppendAsync(Make("e3", severity: Severity.Critical, detectorId: "SEC-02"), CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(MinSeverity: Severity.High), CancellationToken.None))
        {
            results.Add(e);
        }

        Assert.Equal(2, results.Count);
        Assert.All(results, e => Assert.True(e.Severity >= Severity.High));
    }

    [Fact]
    public async Task ConcurrentAppends_AllPersisted_NoCorruption()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var tasks = new List<Task>(50);
        for (int i = 0; i < 50; i++)
        {
            var id = i.ToString(CultureInfo.InvariantCulture);
            tasks.Add(store.AppendAsync(Make("e" + id), CancellationToken.None).AsTask());
        }
        await Task.WhenAll(tasks);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: 1000), CancellationToken.None))
        {
            results.Add(e);
        }
        Assert.Equal(50, results.Count);
    }

    [Fact]
    public async Task Schema_Version1_NewDatabaseInitialised()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var version = await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
        Assert.Equal(1, version);
    }

    [Fact]
    public async Task RetentionPeriod_DeletesOldEntries()
    {
        var oldEntry = new AuditEntry(
            "old-1",
            DateTimeOffset.UtcNow - TimeSpan.FromDays(10),
            "h-old-1",
            null,
            Severity.High,
            "SEC-01",
            "old summary");
        var freshEntry = new AuditEntry(
            "fresh-1",
            DateTimeOffset.UtcNow,
            "h-fresh-1",
            "h-old-1",
            Severity.High,
            "SEC-01",
            "fresh summary");

        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions
        {
            DatabasePath = _dbPath,
            RetentionPeriod = TimeSpan.FromDays(7),
        });
        await store.AppendAsync(oldEntry, CancellationToken.None);
        await store.AppendAsync(freshEntry, CancellationToken.None);

        await store.RunRetentionForTestingAsync(CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
        {
            results.Add(e);
        }
        Assert.Single(results);
        Assert.Equal(freshEntry.Id, results[0].Id);
    }
}
