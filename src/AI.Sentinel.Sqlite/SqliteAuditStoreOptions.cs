namespace AI.Sentinel.Sqlite;

/// <summary>Options for <see cref="SqliteAuditStore"/>.</summary>
public sealed class SqliteAuditStoreOptions
{
    /// <summary>Path to the SQLite database file. Created if missing.</summary>
    public string DatabasePath { get; set; } = "audit.db";

    /// <summary>Optional retention period; entries older than this are deleted by a background timer. Null = retain forever.</summary>
    public TimeSpan? RetentionPeriod { get; set; }

    /// <summary>Interval between retention sweeps. Defaults to one hour.</summary>
    public TimeSpan RetentionSweepInterval { get; set; } = TimeSpan.FromHours(1);
}
