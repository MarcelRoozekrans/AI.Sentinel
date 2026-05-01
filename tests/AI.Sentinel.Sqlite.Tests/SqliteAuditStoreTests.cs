using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
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
    public async Task RoundTrip_AuthorizationDenyWithCode_PreservesPolicyCode()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId("u"),
            receiver: new AgentId("a"),
            session: SessionId.New(),
            callerId: "u1",
            roles: new HashSet<string>(StringComparer.Ordinal),
            toolName: "Bash",
            policyName: "TenantActive",
            reason: "Tenant evicted",
            policyCode: "tenant_inactive");

        await store.AppendAsync(entry, CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
        {
            results.Add(e);
        }
        Assert.Single(results);
        Assert.Equal("tenant_inactive", results[0].PolicyCode);
    }

    [Fact]
    public async Task Schema_Version2_NewDatabaseInitialised()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var version = await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
        Assert.Equal(2, version);
    }

    [Fact]
    public async Task MaxDatabaseSizeBytes_TrimsOldestEntries_AndShrinksFile()
    {
        // Strategy: write a big batch first, measure the resulting file size, configure
        // a cap at half that size, sweep, verify the file actually shrunk and that
        // surviving rows are the newest. We don't pin to an absolute byte count because
        // SQLite has page-size + schema overhead that makes "cap = 16KB" untestable on
        // an empty DB.
        const int batchSize = 500;
        var entries = new List<AuditEntry>(batchSize);
        string? prevHash = null;
        for (int i = 0; i < batchSize; i++)
        {
            var hash = $"h{i:x8}";
            entries.Add(new AuditEntry(
                $"id-{i}", DateTimeOffset.UtcNow.AddSeconds(i), hash, prevHash,
                Severity.Low, "SEC-99", new string('x', 128)));
            prevHash = hash;
        }

        // Phase 1: fill the DB without a cap, measure how big it grows.
        long fullSize;
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            for (int idx = 0; idx < entries.Count; idx++)
            {
                await store.AppendAsync(entries[idx], CancellationToken.None);
            }
        }
        fullSize = new FileInfo(_dbPath).Length;

        // Phase 2: re-open with a cap at ~60% of the full size, sweep, verify shrinkage.
        var capBytes = (long)(fullSize * 0.6);
        await using var capped = new SqliteAuditStore(new SqliteAuditStoreOptions
        {
            DatabasePath = _dbPath,
            MaxDatabaseSizeBytes = capBytes,
        });
        await capped.RunRetentionForTestingAsync(CancellationToken.None);

        var afterSize = new FileInfo(_dbPath).Length;
        Assert.True(afterSize < fullSize,
            $"sweep should shrink the file; before={fullSize} after={afterSize} cap={capBytes}");
        Assert.True(afterSize <= capBytes,
            $"sweep should bring file at-or-under cap; after={afterSize} cap={capBytes}");

        var remaining = new List<AuditEntry>();
        await foreach (var e in capped.QueryAsync(new AuditQuery(PageSize: 10_000), CancellationToken.None))
        {
            remaining.Add(e);
        }
        Assert.NotEmpty(remaining);
        Assert.True(remaining.Count < batchSize, "some rows must have been trimmed");
        // Oldest IDs gone; the most recent entry must still be present.
        Assert.Equal(entries[^1].Id, remaining[^1].Id);
    }

    [Fact]
    public async Task MaxDatabaseSizeBytes_NotConfigured_DoesNotTrim()
    {
        var entries = new List<AuditEntry>();
        string? prevHash = null;
        for (int i = 0; i < 50; i++)
        {
            var hash = $"h{i:x8}";
            entries.Add(new AuditEntry(
                $"id-{i}", DateTimeOffset.UtcNow.AddSeconds(i), hash, prevHash,
                Severity.Low, "SEC-99", "x"));
            prevHash = hash;
        }

        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions
        {
            DatabasePath = _dbPath,
            // No MaxDatabaseSizeBytes — sweep is a no-op for size, no retention either.
        });
        for (int idx = 0; idx < entries.Count; idx++)
        {
            await store.AppendAsync(entries[idx], CancellationToken.None);
        }

        await store.RunRetentionForTestingAsync(CancellationToken.None);

        var count = 0;
        await foreach (var _ in store.QueryAsync(new AuditQuery(PageSize: 1000), CancellationToken.None))
        {
            count++;
        }
        Assert.Equal(50, count);
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
