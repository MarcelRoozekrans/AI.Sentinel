using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Sqlite;

internal static class SqliteSchema
{
    internal const int CurrentVersion = 3;

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
            await CreateFreshSchemaAsync(conn, ct).ConfigureAwait(false);
            return;
        }

        // Single-writer assumption: these migrations are not safe for concurrent first-open from
        // two processes against an out-of-date DB — SQLite will serialize the writes, but the
        // second ALTER throws "duplicate column" instead of being a no-op. Per audit-store
        // design, single-writer is the supported configuration.
        //
        // Each step is independent so a v1 DB walks v1→v2→v3 in one init pass; a v2 DB only
        // runs the v2→v3 step. The final block sets user_version to CurrentVersion.
        if (current < 2) await MigrateV1ToV2Async(conn, ct).ConfigureAwait(false);
        if (current < 3) await MigrateV2ToV3Async(conn, ct).ConfigureAwait(false);
    }

    private static async Task CreateFreshSchemaAsync(SqliteConnection conn, CancellationToken ct)
    {
        // Fresh DB: create the current shape directly (policy_code + session_id columns
        // included) so we never need to run the per-version ALTERs on a brand-new file.
        using var migrate = conn.CreateCommand();
        migrate.CommandText = $"""
            CREATE TABLE IF NOT EXISTS audit_entries (
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
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries (timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_detector  ON audit_entries (detector_id);
            CREATE INDEX IF NOT EXISTS idx_audit_severity  ON audit_entries (severity);
            CREATE INDEX IF NOT EXISTS idx_audit_sequence  ON audit_entries (sequence);
            CREATE INDEX IF NOT EXISTS idx_audit_session   ON audit_entries (session_id);
            PRAGMA user_version = {CurrentVersion};
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task MigrateV1ToV2Async(SqliteConnection conn, CancellationToken ct)
    {
        // Pre-1.6 audit DB: ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT is non-locking
        // on SQLite and existing rows retroactively read the default value.
        using var migrate = conn.CreateCommand();
        migrate.CommandText = """
            ALTER TABLE audit_entries ADD COLUMN policy_code TEXT NOT NULL DEFAULT 'policy_denied';
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task MigrateV2ToV3Async(SqliteConnection conn, CancellationToken ct)
    {
        // v2→v3: add nullable session_id + correlation index for dashboard queries. This is
        // the final step in the chain so it bumps user_version to CurrentVersion.
        using var migrate = conn.CreateCommand();
        migrate.CommandText = $"""
            ALTER TABLE audit_entries ADD COLUMN session_id TEXT;
            CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_entries (session_id);
            PRAGMA user_version = {CurrentVersion};
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    internal static async Task<int> GetVersionAsync(SqliteConnection conn, CancellationToken ct)
    {
        using var versionCmd = conn.CreateCommand();
        versionCmd.CommandText = "PRAGMA user_version;";
        var raw = await versionCmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return raw is null ? 0 : (int)(long)raw;
    }
}
