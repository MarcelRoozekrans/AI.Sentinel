namespace AI.Sentinel.Approvals.Sqlite;

/// <summary>Options for <see cref="SqliteApprovalStore"/>.</summary>
/// <remarks>
/// Several processes on one host can share the database file, such as hook processes that run
/// side by side and a dashboard that resolves their requests. Creating or reusing a request runs
/// under <c>BEGIN IMMEDIATE</c>, and approve and deny each change only a pending row, so the file
/// holds one request per caller and policy and the first decision wins. Do not put the file on a
/// network share.
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
