namespace AI.Sentinel.Approvals.Sqlite;

/// <summary>Options for <see cref="SqliteApprovalStore"/>.</summary>
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
