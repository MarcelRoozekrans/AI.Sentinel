using System.Globalization;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

/// <summary>
/// Schema v5 adds the nullable <c>source</c> column naming the tool that wrote each entry. The
/// hook CLIs and the MCP proxy share one file, so the first open of an out-of-date database can
/// race between processes and must still migrate exactly once.
/// </summary>
public sealed class SqliteSchemaV5MigrationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-v5mig-{Guid.NewGuid():N}.db"));

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

    private string ConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = _dbPath,
        Pooling = false,
        Mode = SqliteOpenMode.ReadWriteCreate,
    }.ToString();

    private async Task ExecuteAsync(string sql)
    {
        await using var conn = new SqliteConnection(ConnectionString);
        await conn.OpenAsync(TestContext.Current.CancellationToken);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private async Task<object?> ScalarAsync(string sql)
    {
        await using var conn = new SqliteConnection(ConnectionString);
        await conn.OpenAsync(TestContext.Current.CancellationToken);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        return await cmd.ExecuteScalarAsync(TestContext.Current.CancellationToken);
    }

    private Task SeedV4DatabaseAsync() => ExecuteAsync("""
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
            session_id    TEXT
        );
        CREATE INDEX idx_audit_sequence ON audit_entries (sequence);
        CREATE INDEX idx_audit_session  ON audit_entries (session_id);
        CREATE TABLE audit_chain_head (
            id   INTEGER PRIMARY KEY CHECK (id = 1),
            hash TEXT NOT NULL
        );
        INSERT INTO audit_entries(id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence)
        VALUES ('detection-1', 0, 3, 'SEC-01', 'h-detection', NULL, 'injection', 1);
        INSERT INTO audit_chain_head (id, hash) VALUES (1, 'h-detection');
        PRAGMA user_version = 4;
        """);

    [Fact]
    public async Task V4Db_MigratesToV5_AddingSource()
    {
        await SeedV4DatabaseAsync();

        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            Assert.Equal(5, await store.GetSchemaVersionForTestingAsync(CancellationToken.None));
        }

        Assert.Equal(0L, await ScalarAsync("""SELECT "notnull" FROM pragma_table_info('audit_entries') WHERE name = 'source';"""));
        Assert.IsType<DBNull>(await ScalarAsync("SELECT source FROM audit_entries WHERE id = 'detection-1';"));
    }

    [Fact]
    public async Task ConcurrentFirstOpen_OfV4Db_Succeeds()
    {
        await SeedV4DatabaseAsync();
        await ExecuteAsync("PRAGMA journal_mode=WAL;");

        // A third connection holds the write lock, so both stores read v4 and then queue on
        // BEGIN IMMEDIATE. Whichever gets the lock second must re-read user_version inside its
        // transaction and skip the ALTER, or it fails on a duplicate column.
        await using var holder = new SqliteConnection(ConnectionString);
        await holder.OpenAsync(TestContext.Current.CancellationToken);
        var hold = holder.BeginTransaction();
        Task<SqliteAuditStore>[] opens =
        [
            Task.Run(() => new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }), TestContext.Current.CancellationToken),
            Task.Run(() => new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }), TestContext.Current.CancellationToken),
        ];
        try
        {
            // Give both constructors time to read the version and block on the lock.
            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
            Assert.All(opens, t => Assert.False(t.IsCompleted));
            hold.Rollback();

            foreach (var store in await Task.WhenAll(opens))
            {
                Assert.Equal(5, await store.GetSchemaVersionForTestingAsync(CancellationToken.None));
            }
            Assert.Equal(1L, await ScalarAsync("SELECT COUNT(*) FROM pragma_table_info('audit_entries') WHERE name = 'source';"));
        }
        finally
        {
            // Release the lock even when an assertion fails, so the constructors finish instead of
            // blocking on the busy timeout, then close every store that opened.
            hold.Dispose();
            foreach (var open in opens)
            {
                try { await (await open).DisposeAsync(); }
                catch (SqliteException) { /* the failure already surfaced through Task.WhenAll */ }
            }
        }
    }
}
