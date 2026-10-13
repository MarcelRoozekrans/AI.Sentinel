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
        AuditEntry stored;
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            stored = await store.AppendAsync(Make("e1"), CancellationToken.None);
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
            Assert.Equal(stored.Hash, results[0].Hash);
            Assert.Equal(Severity.High, results[0].Severity);
            Assert.Equal("SEC-01", results[0].DetectorId);
        }
    }

    private static Task<AuditChainVerification> VerifyAsync(SqliteAuditStore store) =>
        AuditHashChain.VerifyAsync(store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), CancellationToken.None), CancellationToken.None).AsTask();

    [Fact]
    public async Task Append_ReturnsTheEntryExactlyAsQueryReadsItBack()
    {
        // A detection entry has no PolicyCode; the store must hash the value it persists,
        // or every entry it reads back fails verification.
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        var stored = await store.AppendAsync(Make("e1"), CancellationToken.None);

        var read = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
            read.Add(e);
        Assert.Equal(stored, Assert.Single(read));
    }

    [Fact]
    public async Task Append_LinksEachEntryToThePreviousOne()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        var first = await store.AppendAsync(Make("e1"), CancellationToken.None);
        var second = await store.AppendAsync(Make("e2"), CancellationToken.None);

        Assert.Null(first.PreviousHash);
        Assert.Equal(first.Hash, second.PreviousHash);
        Assert.Equal(AuditHashChain.ComputeHash(second), second.Hash);
    }

    [Fact]
    public async Task HashChain_ContinuesAcrossReopen()
    {
        AuditEntry first;
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            first = await store.AppendAsync(Make("e1"), CancellationToken.None);
        }

        await using var reopened = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var second = await reopened.AppendAsync(Make("e2"), CancellationToken.None);

        Assert.Equal(first.Hash, second.PreviousHash);
        var result = await VerifyAsync(reopened);
        Assert.True(result.IsIntact);
        Assert.Equal(2, result.EntriesChecked);
    }

    [Fact]
    public async Task HashChain_EditedRowFailsVerificationAtThatRow()
    {
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            for (var i = 0; i < 5; i++)
                await store.AppendAsync(Make($"e{i}"), CancellationToken.None);
        }

        await using (var raw = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath};Pooling=False"))
        {
            await raw.OpenAsync(TestContext.Current.CancellationToken);
            using var cmd = raw.CreateCommand();
            cmd.CommandText = "UPDATE audit_entries SET severity = 0 WHERE id = 'e2';";
            Assert.Equal(1, await cmd.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        }

        await using var reopened = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var result = await VerifyAsync(reopened);
        Assert.False(result.IsIntact);
        Assert.Equal("e2", result.FirstBrokenEntryId);
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
        var chain = await VerifyAsync(store);
        Assert.True(chain.IsIntact);
        Assert.Equal(50, chain.EntriesChecked);
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
    public async Task Schema_CurrentVersion_NewDatabaseInitialised()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var version = await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
        Assert.Equal(4, version);
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

        // Trimming the head leaves the rest of the chain verifiable from its anchor.
        var chain = await VerifyAsync(capped);
        Assert.True(chain.IsIntact);
        Assert.Equal(remaining.Count, chain.EntriesChecked);
        Assert.NotNull(chain.AnchorHash);
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
        var storedOld = await store.AppendAsync(oldEntry, CancellationToken.None);
        await store.AppendAsync(freshEntry, CancellationToken.None);

        await store.RunRetentionForTestingAsync(CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
        {
            results.Add(e);
        }
        Assert.Single(results);
        Assert.Equal(freshEntry.Id, results[0].Id);

        var chain = await VerifyAsync(store);
        Assert.True(chain.IsIntact);
        Assert.Equal(storedOld.Hash, chain.AnchorHash);
    }

    [Fact]
    public async Task RetentionPeriod_NeverDeletesFromTheMiddleOfTheChain()
    {
        // Callers stamp Timestamp before the store's lock, so concurrent writers can append an
        // older timestamp after a younger one. Retention must only cut a prefix of the chain.
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions
        {
            DatabasePath = _dbPath,
            RetentionPeriod = TimeSpan.FromDays(7),
        });
        var now = DateTimeOffset.UtcNow;
        await store.AppendAsync(Make("expired-1") with { Timestamp = now - TimeSpan.FromDays(10) }, CancellationToken.None);
        await store.AppendAsync(Make("young") with { Timestamp = now - TimeSpan.FromDays(1) }, CancellationToken.None);
        await store.AppendAsync(Make("expired-behind-young") with { Timestamp = now - TimeSpan.FromDays(10) }, CancellationToken.None);
        await store.AppendAsync(Make("fresh") with { Timestamp = now }, CancellationToken.None);

        await store.RunRetentionForTestingAsync(CancellationToken.None);

        var remaining = new List<string>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
            remaining.Add(e.Id);
        Assert.Equal(["young", "expired-behind-young", "fresh"], remaining);
        Assert.True((await VerifyAsync(store)).IsIntact);
    }

    [Fact]
    public async Task HashChain_SurvivesRetentionEmptyingTheTable()
    {
        AuditEntry last;
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions
        {
            DatabasePath = _dbPath,
            RetentionPeriod = TimeSpan.FromDays(7),
        }))
        {
            await store.AppendAsync(Make("old-1") with { Timestamp = DateTimeOffset.UtcNow - TimeSpan.FromDays(10) }, CancellationToken.None);
            last = await store.AppendAsync(Make("old-2") with { Timestamp = DateTimeOffset.UtcNow - TimeSpan.FromDays(9) }, CancellationToken.None);
            await store.RunRetentionForTestingAsync(CancellationToken.None);
        }

        await using var reopened = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var next = await reopened.AppendAsync(Make("after"), CancellationToken.None);

        // A null PreviousHash here would read as "complete from the first entry" and hide the deletion.
        Assert.Equal(last.Hash, next.PreviousHash);
    }

    [Fact]
    public async Task FailedAppend_LeavesTheChainHeadUnchanged()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var first = await store.AppendAsync(Make("e1"), CancellationToken.None);

        await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(
            () => store.AppendAsync(Make("e1"), CancellationToken.None).AsTask());
        var second = await store.AppendAsync(Make("e2"), CancellationToken.None);

        Assert.Equal(first.Hash, second.PreviousHash);
        Assert.True((await VerifyAsync(store)).IsIntact);
    }
}
