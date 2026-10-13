using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Sqlite;

internal static class SqliteSchema
{
    internal const int CurrentVersion = 5;

    // The current shape, used only by the fresh-schema path. policy_code is nullable: only
    // AUTHZ-DENY entries carry one, and the stored value is hashed. source names the tool that
    // wrote the entry and is null for in-process hosts.
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
                session_id    TEXT,
                source        TEXT
        """;

    // The v4 shape, frozen for the v3→v4 table rebuild. The later steps then run on top of it,
    // so it must not gain columns that a later ALTER adds.
    private const string AuditEntriesColumnsV4 = """
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
        // journal_mode cannot change inside a transaction, so set it first. WAL lets readers run
        // alongside the one writer; several writer processes take turns on the write lock.
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
            await pragma.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        // Fast path: an up-to-date file needs no write lock at all.
        if (await GetVersionAsync(conn, null, ct).ConfigureAwait(false) >= CurrentVersion)
        {
            return;
        }

        // Several processes share one file, so two of them can open an out-of-date database at
        // once. BEGIN IMMEDIATE takes the write lock before user_version is read again: the
        // process that waited sees the version the other one committed and skips every step.
        // Disposing an uncommitted transaction rolls it back, so a failed step leaves the file
        // at its old version and unlocked.
        using var tx = conn.BeginTransaction();
        var current = await GetVersionAsync(conn, tx, ct).ConfigureAwait(false);
        if (current >= CurrentVersion)
        {
            return;
        }

        if (current < 1)
        {
            await CreateFreshSchemaAsync(conn, tx, ct).ConfigureAwait(false);
        }
        else
        {
            // Each step is independent so a v1 DB walks every step in one init pass; a v4 DB only
            // runs the v4→v5 step. Each step changes only the shape; the bump below is the one
            // place that writes user_version.
            if (current < 2) await MigrateV1ToV2Async(conn, tx, ct).ConfigureAwait(false);
            if (current < 3) await MigrateV2ToV3Async(conn, tx, ct).ConfigureAwait(false);
            if (current < 4) await MigrateV3ToV4Async(conn, tx, ct).ConfigureAwait(false);
            if (current < 5) await MigrateV4ToV5Async(conn, tx, ct).ConfigureAwait(false);
        }

        using (var bump = conn.CreateCommand())
        {
            bump.Transaction = tx;
            bump.CommandText = $"PRAGMA user_version = {CurrentVersion};";
            await bump.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        await tx.CommitAsync(ct).ConfigureAwait(false);
    }

    private static async Task CreateFreshSchemaAsync(SqliteConnection conn, SqliteTransaction tx, CancellationToken ct)
    {
        // Fresh DB: create the current shape directly so we never need to run the per-version
        // ALTERs on a brand-new file.
        using var migrate = conn.CreateCommand();
        migrate.Transaction = tx;
        migrate.CommandText = $"""
            CREATE TABLE IF NOT EXISTS audit_entries (
            {AuditEntriesColumns}
            );
            {AuditEntriesIndexes}
            {ChainHeadTable}
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task MigrateV1ToV2Async(SqliteConnection conn, SqliteTransaction tx, CancellationToken ct)
    {
        // Pre-1.6 audit DB: ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT is non-locking
        // on SQLite and existing rows retroactively read the default value.
        using var migrate = conn.CreateCommand();
        migrate.Transaction = tx;
        migrate.CommandText = """
            ALTER TABLE audit_entries ADD COLUMN policy_code TEXT NOT NULL DEFAULT 'policy_denied';
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task MigrateV2ToV3Async(SqliteConnection conn, SqliteTransaction tx, CancellationToken ct)
    {
        // v2→v3: add nullable session_id + correlation index for dashboard queries.
        // Pure additive DDL — InitializeAsync owns the user_version bump.
        using var migrate = conn.CreateCommand();
        migrate.Transaction = tx;
        migrate.CommandText = """
            ALTER TABLE audit_entries ADD COLUMN session_id TEXT;
            CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_entries (session_id);
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task MigrateV3ToV4Async(SqliteConnection conn, SqliteTransaction tx, CancellationToken ct)
    {
        // v3→v4: SQLite cannot drop NOT NULL in place, so rebuild audit_entries with a nullable
        // policy_code. Detection rows only ever held the old column default, so they become NULL;
        // AUTHZ-DENY rows keep their code. The chain head is seeded from the newest row, so the
        // first 3.0 entry links to the last entry written before the upgrade.
        using var migrate = conn.CreateCommand();
        migrate.Transaction = tx;
        migrate.CommandText = $"""
            DROP TABLE IF EXISTS audit_entries_v4;
            CREATE TABLE audit_entries_v4 (
            {AuditEntriesColumnsV4}
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
            """;
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task MigrateV4ToV5Async(SqliteConnection conn, SqliteTransaction tx, CancellationToken ct)
    {
        // v4→v5: add the nullable source column. Existing rows read NULL, which is what they were
        // hashed with, so the chain still verifies.
        using var migrate = conn.CreateCommand();
        migrate.Transaction = tx;
        migrate.CommandText = "ALTER TABLE audit_entries ADD COLUMN source TEXT;";
        await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    internal static Task<int> GetVersionAsync(SqliteConnection conn, CancellationToken ct) =>
        GetVersionAsync(conn, null, ct);

    private static async Task<int> GetVersionAsync(SqliteConnection conn, SqliteTransaction? tx, CancellationToken ct)
    {
        using var versionCmd = conn.CreateCommand();
        versionCmd.Transaction = tx;
        versionCmd.CommandText = "PRAGMA user_version;";
        var raw = await versionCmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return raw is null ? 0 : (int)(long)raw;
    }
}
