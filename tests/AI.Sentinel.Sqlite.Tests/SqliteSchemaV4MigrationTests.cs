using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

/// <summary>
/// Schema v4 makes <c>policy_code</c> nullable, so a detection entry is stored, hashed and
/// forwarded with the <see langword="null"/> PolicyCode it was written with, and adds the
/// one-row <c>audit_chain_head</c> table that keeps the chain head when retention empties the table.
/// </summary>
public sealed class SqliteSchemaV4MigrationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-v4mig-{Guid.NewGuid():N}.db"));

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

    private Task SeedV3DatabaseAsync() => ExecuteAsync("""
        CREATE TABLE audit_entries (
            id            TEXT PRIMARY KEY,
            timestamp     INTEGER NOT NULL,
            severity      INTEGER NOT NULL,
            detector_id   TEXT NOT NULL,
            hash          TEXT NOT NULL,
            previous_hash TEXT,
            summary       TEXT NOT NULL,
            sequence      INTEGER NOT NULL,
            policy_code   TEXT NOT NULL DEFAULT 'policy_denied',
            session_id    TEXT
        );
        CREATE INDEX idx_audit_sequence ON audit_entries (sequence);
        INSERT INTO audit_entries(id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence, session_id)
        VALUES ('detection-1', 0, 3, 'SEC-01', 'h-detection', NULL, 'injection', 1, 's1');
        INSERT INTO audit_entries(id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence, policy_code)
        VALUES ('denial-1', 1, 3, 'AUTHZ-DENY', 'h-denial', NULL, 'denied', 2, 'tenant_inactive');
        PRAGMA user_version = 3;
        """);

    [Fact]
    public async Task FreshDb_PolicyCodeIsNullable()
    {
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            Assert.Equal(4, await store.GetSchemaVersionForTestingAsync(CancellationToken.None));
        }

        Assert.Equal(0L, await ScalarAsync("""SELECT "notnull" FROM pragma_table_info('audit_entries') WHERE name = 'policy_code';"""));
    }

    [Fact]
    public async Task DetectionEntry_KeepsANullPolicyCode()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        var stored = await store.AppendAsync(
            new AuditEntry("e1", DateTimeOffset.UtcNow, string.Empty, null, Severity.High, "SEC-01", "injection"),
            CancellationToken.None);

        Assert.Null(stored.PolicyCode);
        var read = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
            read.Add(e);
        Assert.Equal(stored, Assert.Single(read));
    }

    [Fact]
    public async Task V3Db_MigratesToV4_ClearingTheDefaultOnlyOnDetectionRows()
    {
        await SeedV3DatabaseAsync();

        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            Assert.Equal(4, await store.GetSchemaVersionForTestingAsync(CancellationToken.None));
        }

        Assert.IsType<DBNull>(await ScalarAsync("SELECT policy_code FROM audit_entries WHERE id = 'detection-1';"));
        Assert.Equal("tenant_inactive", await ScalarAsync("SELECT policy_code FROM audit_entries WHERE id = 'denial-1';"));
        Assert.Equal("s1", await ScalarAsync("SELECT session_id FROM audit_entries WHERE id = 'detection-1';"));
        Assert.Equal(2L, await ScalarAsync("SELECT COUNT(*) FROM pragma_index_list('audit_entries') WHERE name IN ('idx_audit_sequence', 'idx_audit_session');"));
    }

    [Fact]
    public async Task V3Db_MigratesToV4_ContinuingTheChainFromTheNewestRow()
    {
        await SeedV3DatabaseAsync();

        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var first = await store.AppendAsync(
            new AuditEntry("e1", DateTimeOffset.UtcNow, string.Empty, null, Severity.High, "SEC-01", "after upgrade"),
            CancellationToken.None);

        Assert.Equal("h-denial", first.PreviousHash);
    }

    [Fact]
    public async Task FailedV4Migration_RollsBackAndReleasesTheFile()
    {
        await SeedV3DatabaseAsync();
        // A view under the chain-head name makes the migration's last statement fail, after the
        // table rebuild has already written inside the transaction.
        await ExecuteAsync("CREATE VIEW audit_chain_head AS SELECT 1 AS id, 'x' AS hash;");

        Assert.ThrowsAny<SqliteException>(() => new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }));

        // The failed open must not keep a write lock: a short timeout turns a leaked lock into a fast failure.
        var csb = new SqliteConnectionStringBuilder(ConnectionString) { DefaultTimeout = 1 };
        await using var conn = new SqliteConnection(csb.ToString());
        await conn.OpenAsync(TestContext.Current.CancellationToken);
        using var write = conn.CreateCommand();
        write.CommandText = "BEGIN IMMEDIATE; ROLLBACK;";
        await write.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);

        using var version = conn.CreateCommand();
        version.CommandText = "PRAGMA user_version;";
        Assert.Equal(3L, await version.ExecuteScalarAsync(TestContext.Current.CancellationToken));
        using var notNull = conn.CreateCommand();
        notNull.CommandText = """SELECT "notnull" FROM pragma_table_info('audit_entries') WHERE name = 'policy_code';""";
        Assert.Equal(1L, await notNull.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }
}
