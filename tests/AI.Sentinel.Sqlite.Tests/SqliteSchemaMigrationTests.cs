using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Sqlite;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

public sealed class SqliteSchemaMigrationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-mig-{Guid.NewGuid():N}.db"));

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
    public async Task Migration_FromV1ToCurrent_AddsPolicyCodeColumnWithDefault()
    {
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Pooling = false,
            Mode = SqliteOpenMode.ReadWriteCreate,
        };

        // Step 1: manually emulate a pre-1.6 (v1) database with a legacy AUTHZ-DENY row.
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

        // Step 2: opening a SqliteAuditStore runs the migration.
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            var version = await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
            Assert.Equal(3, version);
        }

        // Step 3: open a fresh raw connection and verify the legacy row was backfilled.
        await using (var conn = new SqliteConnection(csb.ToString()))
        {
            await conn.OpenAsync();
            using var queryCmd = conn.CreateCommand();
            queryCmd.CommandText = "SELECT policy_code FROM audit_entries WHERE id='legacy-1';";
            var raw = await queryCmd.ExecuteScalarAsync();
            Assert.Equal("policy_denied", raw);
        }
    }

    [Fact]
    public async Task FreshDatabase_LandsAtCurrentVersion_Directly()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var version = await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
        Assert.Equal(3, version);
    }
}
