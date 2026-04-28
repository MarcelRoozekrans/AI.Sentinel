using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Sqlite;

internal static class SqliteSchema
{
    internal const int CurrentVersion = 1;

    internal static async Task InitializeAsync(SqliteConnection conn, CancellationToken ct)
    {
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
            await pragma.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        long current;
        using (var versionCmd = conn.CreateCommand())
        {
            versionCmd.CommandText = "PRAGMA user_version;";
            var raw = await versionCmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
            current = raw is null ? 0L : (long)raw;
        }

        if (current < 1)
        {
            using var migrate = conn.CreateCommand();
            migrate.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id            TEXT PRIMARY KEY,
                    timestamp     INTEGER NOT NULL,
                    severity      INTEGER NOT NULL,
                    detector_id   TEXT NOT NULL,
                    hash          TEXT NOT NULL,
                    previous_hash TEXT,
                    summary       TEXT NOT NULL,
                    sequence      INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries (timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_detector  ON audit_entries (detector_id);
                CREATE INDEX IF NOT EXISTS idx_audit_severity  ON audit_entries (severity);
                CREATE INDEX IF NOT EXISTS idx_audit_sequence  ON audit_entries (sequence);
                PRAGMA user_version = 1;
                """;
            await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }

    internal static async Task<int> GetVersionAsync(SqliteConnection conn, CancellationToken ct)
    {
        using var versionCmd = conn.CreateCommand();
        versionCmd.CommandText = "PRAGMA user_version;";
        var raw = await versionCmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return raw is null ? 0 : (int)(long)raw;
    }
}
