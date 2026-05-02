using System.Globalization;
using AI.Sentinel.Audit;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

/// <summary>
/// Schema v3 introduces a nullable <c>session_id TEXT</c> column on <c>audit_entries</c> plus
/// an <c>idx_audit_session</c> index for dashboard correlation queries. These tests pin the
/// fresh-DB shape and the v1→v3 walk so future migrations can't silently drop the column or
/// the index, and so a v1 → v3 jump still picks up both ALTERs in one schema-init pass.
/// </summary>
public sealed class SqliteSchemaV3MigrationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-v3mig-{Guid.NewGuid():N}.db"));

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
    public async Task FreshDb_HasV3Schema()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var version = await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
        Assert.Equal(3, version);
    }

    [Fact]
    public async Task FreshDb_AuditEntriesTable_HasSessionIdColumn()
    {
        // Step 1: drive schema init via SqliteAuditStore.
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
        }

        // Step 2: open a fresh raw connection and inspect column metadata.
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Pooling = false,
            Mode = SqliteOpenMode.ReadOnly,
        };
        await using var conn = new SqliteConnection(csb.ToString());
        await conn.OpenAsync();

        // session_id column: TEXT, nullable (notnull=0).
        using (var colCmd = conn.CreateCommand())
        {
            colCmd.CommandText = """
                SELECT type, "notnull" FROM pragma_table_info('audit_entries')
                 WHERE name = 'session_id';
                """;
            await using var reader = await colCmd.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync(), "session_id column not found on audit_entries");
            Assert.Equal("TEXT", reader.GetString(0));
            Assert.Equal(0, reader.GetInt32(1));
        }

        // idx_audit_session index on audit_entries.
        using (var idxCmd = conn.CreateCommand())
        {
            idxCmd.CommandText = """
                SELECT name FROM pragma_index_list('audit_entries')
                 WHERE name = 'idx_audit_session';
                """;
            var raw = (string?)await idxCmd.ExecuteScalarAsync();
            Assert.Equal("idx_audit_session", raw);
        }
    }

    [Fact]
    public async Task V1Db_MigratesToV3_AndHasBothNewColumns()
    {
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Pooling = false,
            Mode = SqliteOpenMode.ReadWriteCreate,
        };

        // Step 1: hand-roll a v1 DB (no policy_code, no session_id).
        await using (var conn = new SqliteConnection(csb.ToString()))
        {
            await conn.OpenAsync();
            using var seed = conn.CreateCommand();
            seed.CommandText = """
                CREATE TABLE audit_entries (
                    id            TEXT PRIMARY KEY,
                    timestamp     INTEGER NOT NULL,
                    severity      INTEGER NOT NULL,
                    detector_id   TEXT NOT NULL,
                    hash          TEXT NOT NULL,
                    previous_hash TEXT,
                    summary       TEXT NOT NULL,
                    sequence      INTEGER NOT NULL
                );
                INSERT INTO audit_entries(id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence)
                VALUES ('legacy-1', 0, 4, 'AUTHZ-DENY', 'h', NULL, 'old denial', 1);
                PRAGMA user_version = 1;
                """;
            await seed.ExecuteNonQueryAsync();
        }

        // Step 2: opening a SqliteAuditStore must walk v1→v2→v3 in one init pass.
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            var version = await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
            Assert.Equal(3, version);
        }

        // Step 3: verify both new columns exist on a fresh raw connection.
        await using (var conn = new SqliteConnection(csb.ToString()))
        {
            await conn.OpenAsync();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT name FROM pragma_table_info('audit_entries')
                 WHERE name IN ('policy_code', 'session_id')
                 ORDER BY name;
                """;
            var found = new List<string>();
            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync()) found.Add(reader.GetString(0));
            Assert.Equal(new[] { "policy_code", "session_id" }, found.ToArray());
        }
    }
}
