namespace AI.Sentinel.Sqlite;

/// <summary>Options for <see cref="SqliteAuditStore"/>.</summary>
public sealed class SqliteAuditStoreOptions
{
    /// <summary>Path to the SQLite database file. Created if missing.</summary>
    public string DatabasePath { get; set; } = "audit.db";

    /// <summary>Optional retention period; entries older than this are deleted by a background timer. Null = retain forever.</summary>
    public TimeSpan? RetentionPeriod { get; set; }

    /// <summary>
    /// Optional cap on the database size, measured as used bytes (pages in use times page size). When it exceeds this, the
    /// background sweep deletes the oldest entries (in 10%-of-rows batches, minimum 100)
    /// and runs <c>VACUUM</c> to reclaim space until the file is back under the cap.
    /// Defence in depth against a runaway detector filling the disk faster than time-based
    /// retention can kick in. Null = no size cap.
    /// </summary>
    public long? MaxDatabaseSizeBytes { get; set; }

    /// <summary>
    /// How long a write waits for another process's write lock before giving up with a
    /// <c>SqliteException</c>. Maps to the connection's <c>DefaultTimeout</c>, which also bounds
    /// every command. Rounded up to whole seconds. Short-lived writers should lower this so a busy
    /// database never stalls them. Defaults to 30 seconds.
    /// </summary>
    public TimeSpan BusyTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// When true, the store applies <see cref="MaxDatabaseSizeBytes"/> once while opening, instead
    /// of waiting for the retention timer. Short-lived processes never live long enough for the
    /// timer to fire. Defaults to false.
    /// </summary>
    public bool EnforceSizeCapOnOpen { get; set; }

    /// <summary>
    /// When true, trimming for <see cref="MaxDatabaseSizeBytes"/> ends with <c>VACUUM</c> and a WAL
    /// truncate so the file shrinks. Set false for short-lived writers: <c>VACUUM</c> holds the
    /// cross-process write lock for a long time. Freed pages are then reused rather than returned
    /// to the file system. Defaults to true.
    /// </summary>
    public bool VacuumAfterTrim { get; set; } = true;

    /// <summary>Interval between retention sweeps. Defaults to one hour.</summary>
    public TimeSpan RetentionSweepInterval { get; set; } = TimeSpan.FromHours(1);
}
