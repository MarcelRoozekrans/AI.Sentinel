using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

/// <summary>
/// Schema v7 gives every audit file a random identity and a durable sequence counter (#713). Sequences come from the counter, not
/// from the rows that are left, so retention never makes a sequence come back, and a reader can tell one audit file from another.
/// </summary>
public sealed class SqliteSchemaV7MigrationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-v7mig-{Guid.NewGuid():N}.db"));

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var path in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private string ConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = _dbPath,
        Pooling = false,
        Mode = SqliteOpenMode.ReadWriteCreate,
    }.ToString();

    private async Task<object?> ExecuteAsync(string sql)
    {
        await using var conn = new SqliteConnection(ConnectionString);
        await conn.OpenAsync(TestContext.Current.CancellationToken);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        return await cmd.ExecuteScalarAsync(TestContext.Current.CancellationToken);
    }

    private Task SeedV6DatabaseAsync() => ExecuteAsync("""
        CREATE TABLE audit_entries (
            id            TEXT PRIMARY KEY,
            timestamp     INTEGER NOT NULL,
            severity      INTEGER NOT NULL,
            detector_id   TEXT NOT NULL,
            hash          TEXT NOT NULL,
            previous_hash TEXT,
            summary       TEXT NOT NULL,
            sequence      INTEGER NOT NULL,
            policy_code   TEXT,
            session_id    TEXT,
            source        TEXT,
            tool_kind     TEXT,
            node          TEXT
        );
        CREATE INDEX idx_audit_sequence ON audit_entries (sequence);
        CREATE TABLE audit_chain_head (
            id   INTEGER PRIMARY KEY CHECK (id = 1),
            hash TEXT NOT NULL
        );
        INSERT INTO audit_entries(id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence)
        VALUES ('e-4', 0, 3, 'SEC-01', 'h-4', 'h-3', 'four', 4), ('e-5', 0, 3, 'SEC-01', 'h-5', 'h-4', 'five', 5);
        INSERT INTO audit_chain_head (id, hash) VALUES (1, 'h-5');
        PRAGMA user_version = 6;
        """);

    private static AuditEntry Entry(string summary) =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, string.Empty, null, Severity.Low, "SEC-01", summary);

    private SqliteAuditStore Open() => new(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

    [Fact]
    public async Task V6Db_MigratesToV7_WithAFileIdAndTheCounterAtTheLastSequence()
    {
        await SeedV6DatabaseAsync();

        await using (var store = Open())
        {
            Assert.Equal(7, await store.GetSchemaVersionForTestingAsync(CancellationToken.None));
            var page = await store.ReadAfterAsync(0, 10, CancellationToken.None);
            Assert.Matches("^[0-9a-f]{32}$", page.FileId);
            Assert.Equal(5, page.LastAssigned);
            await store.AppendAsync(Entry("six"), CancellationToken.None);
        }

        Assert.Equal(6L, await ExecuteAsync("SELECT MAX(sequence) FROM audit_entries;"));
        Assert.Equal(6L, await ExecuteAsync("SELECT last_sequence FROM audit_file WHERE id = 1;"));
    }

    [Fact]
    public async Task A_sequence_never_comes_back_after_retention_deleted_every_entry()
    {
        await using var store = Open();
        for (var i = 0; i < 3; i++)
        {
            await store.AppendAsync(Entry($"e{i}"), CancellationToken.None);
        }

        await ExecuteAsync("DELETE FROM audit_entries;");
        await store.AppendAsync(Entry("after"), CancellationToken.None);

        var page = await store.ReadAfterAsync(0, 10, CancellationToken.None);
        Assert.Equal(4, Assert.Single(page.Rows).Sequence);
        Assert.Equal(4, page.LastAssigned);
    }

    [Fact]
    public async Task An_empty_audit_still_reports_the_last_sequence_it_assigned()
    {
        await using var store = Open();
        await store.AppendAsync(Entry("one"), CancellationToken.None);
        await store.AppendAsync(Entry("two"), CancellationToken.None);
        await ExecuteAsync("DELETE FROM audit_entries;");

        var page = await store.ReadAfterAsync(0, 10, CancellationToken.None);

        Assert.Empty(page.Rows);
        Assert.Equal(2, page.LastAssigned);
    }

    [Fact]
    public async Task A_counter_behind_the_rows_never_hands_out_a_sequence_twice()
    {
        // A writer older than v7 that opens a v7 file appends by MAX(sequence) and leaves the counter where it was.
        await using var store = Open();
        await store.AppendAsync(Entry("one"), CancellationToken.None);
        await ExecuteAsync("""
            INSERT INTO audit_entries(id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence)
            VALUES ('old-writer', 0, 1, 'SEC-01', 'h-x', NULL, 'by an old writer', 2);
            """);

        await store.AppendAsync(Entry("three"), CancellationToken.None);

        Assert.Equal(1L, await ExecuteAsync("SELECT COUNT(*) FROM audit_entries WHERE sequence = 3;"));
        Assert.Equal(3L, await ExecuteAsync("SELECT last_sequence FROM audit_file WHERE id = 1;"));
    }

    [Fact]
    public async Task An_entry_from_an_older_writer_moves_the_counter_so_its_sequence_never_comes_back()
    {
        await using var store = Open();
        await store.AppendAsync(Entry("one"), CancellationToken.None);
        // A writer older than v7 appends by MAX(sequence) and knows nothing of audit_file; then retention empties the table.
        await ExecuteAsync("""
            INSERT INTO audit_entries(id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence)
            VALUES ('old-writer', 0, 1, 'SEC-01', 'h-x', NULL, 'by an old writer', 2);
            DELETE FROM audit_entries;
            """);

        await store.AppendAsync(Entry("three"), CancellationToken.None);

        var page = await store.ReadAfterAsync(0, 10, CancellationToken.None);
        Assert.Equal(3, Assert.Single(page.Rows).Sequence);
    }

    [Fact]
    public async Task Each_audit_file_has_its_own_id_and_keeps_it()
    {
        string first;
        await using (var store = Open())
        {
            first = (await store.ReadAfterAsync(0, 1, CancellationToken.None)).FileId;
        }

        await using (var again = Open())
        {
            Assert.Equal(first, (await again.ReadAfterAsync(0, 1, CancellationToken.None)).FileId);
        }

        var otherPath = _dbPath + ".other.db";
        try
        {
            await using var other = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = otherPath });
            Assert.False(string.Equals(first, (await other.ReadAfterAsync(0, 1, CancellationToken.None)).FileId, StringComparison.Ordinal));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var path in new[] { otherPath, otherPath + "-wal", otherPath + "-shm" })
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task A_read_only_open_reads_the_file_id_and_counter()
    {
        string id;
        await using (var store = Open())
        {
            await store.AppendAsync(Entry("one"), CancellationToken.None);
            id = (await store.ReadAfterAsync(0, 1, CancellationToken.None)).FileId;
        }

        await using var reader = SqliteAuditStore.OpenReadOnly(_dbPath);
        var page = await reader.ReadAfterAsync(0, 10, CancellationToken.None);

        Assert.Equal(id, page.FileId);
        Assert.Equal(1, page.LastAssigned);
    }
}
