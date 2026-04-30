namespace AI.Sentinel.Approvals.Sqlite;

/// <summary>Options for <see cref="SqliteApprovalStore"/>.</summary>
/// <remarks>
/// Single writer process. The store uses an in-process <c>SemaphoreSlim</c> to serialise
/// writes; it does NOT use SQLite <c>BEGIN IMMEDIATE</c> transactions, so two processes
/// opening the same database file concurrently can race on the read-then-write paths.
/// Multi-process scenarios require external coordination (e.g., file lock) or a different
/// backend.
/// </remarks>
public sealed class SqliteApprovalStoreOptions
{
    /// <summary>Path to the SQLite database file. Created if missing.</summary>
    public required string DatabasePath { get; set; }

    /// <summary>
    /// Polling interval for <see cref="IApprovalStore.WaitForDecisionAsync"/>. The store
    /// re-queries the database on this cadence until the request transitions out of
    /// Pending or the host's timeout elapses. Defaults to 500 ms.
    /// </summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromMilliseconds(500);
}
