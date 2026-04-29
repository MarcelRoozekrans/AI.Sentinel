namespace AI.Sentinel.Sqlite;

/// <summary>Options for <see cref="SqliteAuditStore"/>.</summary>
public sealed class SqliteAuditStoreOptions
{
    /// <summary>Path to the SQLite database file. Created if missing.</summary>
    public string DatabasePath { get; set; } = "audit.db";

    /// <summary>Optional retention period; entries older than this are deleted by a background timer. Null = retain forever.</summary>
    public TimeSpan? RetentionPeriod { get; set; }

    /// <summary>
    /// Optional cap on the on-disk database file size. When the file exceeds this, the
    /// background sweep deletes the oldest entries (in 10%-of-rows batches, minimum 100)
    /// and runs <c>VACUUM</c> to reclaim space until the file is back under the cap.
    /// Defence in depth against a runaway detector filling the disk faster than time-based
    /// retention can kick in. Null = no size cap.
    /// </summary>
    public long? MaxDatabaseSizeBytes { get; set; }

    /// <summary>Interval between retention sweeps. Defaults to one hour.</summary>
    public TimeSpan RetentionSweepInterval { get; set; } = TimeSpan.FromHours(1);
}
