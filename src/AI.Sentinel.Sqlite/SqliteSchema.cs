using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Sqlite;

internal static class SqliteSchema
{
    internal const int CurrentVersion = 4;

    // Shared by the fresh-schema path and the v3→v4 table rebuild, so both land on the same shape.
    // policy_code is nullable: only AUTHZ-DENY entries carry one, and the stored value is hashed.
    private const string AuditEntriesColumns = """
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
        """;

    private const string AuditEntriesIndexes = """
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries (timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_detector  ON audit_entries (detector_id);
        CREATE INDEX IF NOT EXISTS idx_audit_severity  ON audit_entries (severity);
        CREATE INDEX IF NOT EXISTS idx_audit_sequence  ON audit_entries (sequence);
        CREATE INDEX IF NOT EXISTS idx_audit_session   ON audit_entries (session_id);
        """;

    // One row holding the Hash of the last appended entry. Kept apart from audit_entries so the
    // chain continues even after retention deletes every entry.
    private const string ChainHeadTable = """
        CREATE TABLE IF NOT EXISTS audit_chain_head (
            id   INTEGER PRIMARY KEY CHECK (id = 1),
            hash TEXT NOT NULL
        );
        """;

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
        if (current < 4) await MigrateV3ToV4Async(conn, ct).ConfigureAwait(false);

        // Single, explicit version-bump after all migration steps complete.
        // Each MigrateXToYAsync helper changes only the shape; only this line updates
        // user_version, so adding future migrations is one-line-mechanical. v3→v4 rebuilds
        // the table inside its own transaction, so an interrupted run leaves v3 intact.
        if (current < CurrentVersion)
        {
            using var bump = conn.CreateCommand();
            bump.CommandText = $"PRAGMA user_version = {CurrentVersion};";
            await bump.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }

    private static async Task CreateFreshSchemaAsync(SqliteConnection conn, CancellationToken ct)
    {
        // Fresh DB: create the current shape directly (policy_code + session_id columns
        // included) so we never need to run the per-version ALTERs on a brand-new file.
        using var migrate = conn.CreateCommand();
        migrate.CommandText = $"""
            CREATE TABLE IF NOT EXISTS audit_entries (
            {AuditEntriesColumns}
            );
            {AuditEntriesIndexes}
            {ChainHeadTable}
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
        // v2→v3: add nullable session_id + correlation index for dashboard queries.
        // Pure additive DDL — InitializeAsync owns the user_version bump.
        using var migrate = conn.CreateCommand();
        migrate.CommandText = """
            ALTER TABLE audit_entries ADD COLUMN session_id TEXT;
            CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_entries (session_id);
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task MigrateV3ToV4Async(SqliteConnection conn, CancellationToken ct)
    {
        // v3→v4: SQLite cannot drop NOT NULL in place, so rebuild audit_entries with a nullable
        // policy_code. Detection rows only ever held the old column default, so they become NULL;
        // AUTHZ-DENY rows keep their code. The chain head is seeded from the newest row, so the
        // first 3.0 entry links to the last entry written before the upgrade.
        using var migrate = conn.CreateCommand();
        migrate.CommandText = $"""
            BEGIN;
            DROP TABLE IF EXISTS audit_entries_v4;
            CREATE TABLE audit_entries_v4 (
            {AuditEntriesColumns}
            );
            INSERT INTO audit_entries_v4
                (id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence, policy_code, session_id)
            SELECT id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence,
                   CASE WHEN detector_id = 'AUTHZ-DENY' THEN policy_code ELSE NULL END,
                   session_id
              FROM audit_entries;
            DROP TABLE audit_entries;
            ALTER TABLE audit_entries_v4 RENAME TO audit_entries;
            {AuditEntriesIndexes}
            {ChainHeadTable}
            INSERT OR REPLACE INTO audit_chain_head (id, hash)
            SELECT 1, hash FROM audit_entries ORDER BY sequence DESC LIMIT 1;
            COMMIT;
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
