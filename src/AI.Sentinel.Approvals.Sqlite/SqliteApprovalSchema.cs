using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Approvals.Sqlite;

internal static class SqliteApprovalSchema
{
    internal const int CurrentVersion = 1;

    internal static async Task InitializeAsync(SqliteConnection conn, CancellationToken ct)
    {
        // WAL + NORMAL synchronous: same balance the audit store uses. Concurrent
        // writers are serialised through a SemaphoreSlim in the store; WAL gives
        // readers (the dashboard 'list pending' query) a snapshot that doesn't
        // block writes.
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
            // Timestamps stored as INTEGER UtcTicks; reconstructed via
            // new DateTimeOffset(ticks, TimeSpan.Zero). See requested_at, approved_at, denied_at.
            using var migrate = conn.CreateCommand();
            migrate.CommandText = """
                CREATE TABLE IF NOT EXISTS approval_requests (
                    id                   TEXT PRIMARY KEY,
                    caller_id            TEXT NOT NULL,
                    policy_name          TEXT NOT NULL,
                    tool_name            TEXT NOT NULL,
                    args_json            TEXT NOT NULL,
                    justification        TEXT,
                    requested_at         INTEGER NOT NULL,
                    grant_duration_ticks INTEGER NOT NULL,
                    status               TEXT NOT NULL,
                    approved_at          INTEGER,
                    denied_at            INTEGER,
                    deny_reason          TEXT,
                    approver_id          TEXT,
                    approver_note        TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_approvals_dedupe   ON approval_requests (caller_id, policy_name);
                CREATE INDEX IF NOT EXISTS idx_approvals_status   ON approval_requests (status);
                PRAGMA user_version = 1;
                """;
            await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }
}
