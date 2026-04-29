---
sidebar_position: 3
title: SQLite
---

# SQLite audit store

`AI.Sentinel.Sqlite` ships `SqliteAuditStore` — a persistent `IAuditStore` backed by a single-file SQLite database. Hash-chain integrity preserved across process restarts. Time-based retention sweep. WAL journal mode for concurrent readers.

This is a **store**, not a forwarder. It replaces the default in-memory `RingBufferAuditStore`. Last-registration-wins for `IAuditStore`.

## Wire it up

```bash
dotnet add package AI.Sentinel.Sqlite
```

```csharp
services.AddAISentinel(opts => /* ... */);
services.AddSentinelSqliteStore(opts =>
{
    opts.DatabasePath = "/var/lib/ai-sentinel/audit.db";
    opts.RetentionPeriod = TimeSpan.FromDays(90);          // optional
    opts.RetentionSweepInterval = TimeSpan.FromHours(1);   // optional
});
```

The database file is created at startup if it doesn't exist. Schema is auto-migrated. WAL journal mode is enabled for concurrent reader safety while a single writer (this process) holds the write lock.

## Schema

```sql
CREATE TABLE IF NOT EXISTS audit_entries (
    id              TEXT PRIMARY KEY,
    timestamp       INTEGER NOT NULL,    -- Unix milliseconds
    hash            TEXT NOT NULL,
    previous_hash   TEXT,
    severity        INTEGER NOT NULL,    -- enum value
    detector_id     TEXT NOT NULL,
    summary         TEXT NOT NULL
);

CREATE INDEX idx_timestamp ON audit_entries(timestamp);
CREATE INDEX idx_severity_timestamp ON audit_entries(severity, timestamp);
CREATE INDEX idx_detector_timestamp ON audit_entries(detector_id, timestamp);
```

Indexes optimize the common `AuditQuery` filter combinations (time range, min severity, detector ID).

## Performance

- Append: ~100–500 µs on local SSD (single-row INSERT in WAL mode)
- Query: streams via `IAsyncEnumerable<AuditEntry>` — millions of rows iterable without loading them
- Concurrent readers safe (WAL); writer is single-threaded behind a `SemaphoreSlim`

The pipeline cost of using SQLite over RingBuffer is the difference between &lt;5 µs (memory) and ~100 µs (disk). For most chat workloads this is invisible — the LLM round-trip dominates by 4+ orders of magnitude.

## Hash chain across restarts

The store reloads the most recent `Hash` at startup so the next entry chains correctly. Tampering with the SQLite file (deleting rows, modifying severity) breaks the chain at the tampered entry — every subsequent entry's `previous_hash` no longer matches.

To verify a database file:

```csharp
var sqlite = sp.GetRequiredService<IAuditStore>();
string? prevHash = null;
await foreach (var entry in sqlite.QueryAsync(new AuditQuery(), ct))
{
    if (entry.PreviousHash != prevHash) throw new TamperingDetectedException(entry.Id);
    var expected = ComputeHash(prevHash, entry.Id, entry.Timestamp,
                               entry.DetectorId, entry.Severity, entry.Summary);
    if (entry.Hash != expected) throw new TamperingDetectedException(entry.Id);
    prevHash = entry.Hash;
}
```

A built-in CLI verifier (`AI.Sentinel.Cli verify`) is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md).

## Retention

Two retention strategies in v1:

### Time-based sweep (built-in)

```csharp
opts.RetentionPeriod = TimeSpan.FromDays(90);
opts.RetentionSweepInterval = TimeSpan.FromHours(1);
```

A background timer fires every `RetentionSweepInterval` and runs `DELETE FROM audit_entries WHERE timestamp < ?` for entries older than `RetentionPeriod`. Default sweep interval is 1 hour; default retention period is `null` (no expiry — keep forever).

The sweep is best-effort. It runs while the process is alive; if the process restarts, the timer resets. Old entries persist across restarts until the next sweep tick fires.

Long retention periods are fine — SQLite handles billions of rows without performance degradation given proper indexes (which the schema provides).

### Size-based cap (backlog)

`MaxDatabaseSizeBytes` — delete oldest entries until under the cap — is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). Today, time-based retention is the only built-in mechanism. For size-bounded behavior, set a tighter `RetentionPeriod` and rely on traffic patterns.

## Deployment patterns

### Single-instance with persistent volume

Mount a volume at `/var/lib/ai-sentinel`. Database file persists across container restarts and rolling deployments. Each instance has its own DB.

```yaml
# docker-compose.yml fragment
services:
  app:
    image: my-app
    volumes:
      - ai-sentinel-data:/var/lib/ai-sentinel
    environment:
      - AISentinel__SqliteDatabasePath=/var/lib/ai-sentinel/audit.db
volumes:
  ai-sentinel-data:
```

### Multi-instance (each with its own DB)

Each replica writes to its own file. The hash chain is per-instance. For unified central view, also register a forwarder ([Azure Sentinel](./azure-sentinel) or [OpenTelemetry](./opentelemetry)) that pushes to a centralized SIEM.

```csharp
services.AddAISentinel(opts => /* ... */);
services.AddSentinelSqliteStore(opts => opts.DatabasePath = "/var/lib/ai-sentinel/audit.db");
services.AddSentinelOpenTelemetryForwarder();
// SQLite is the local source of truth; OTel ships a copy to central observability
```

### Multi-instance with shared central DB

Not supported in v1. SQLite isn't designed for multi-writer access across machines. For multi-instance shared storage, use a forwarder to push entries into a central system (Postgres-backed audit store is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) for that scenario).

## Backups

The SQLite file is the audit record. Treat it like any other production database:

- Snapshot the volume periodically
- Use SQLite's `BACKUP` API for online consistent snapshots:
  ```bash
  sqlite3 /var/lib/ai-sentinel/audit.db ".backup '/backup/audit-$(date +%Y%m%d).db'"
  ```
- Keep at least one backup outside the rotation window of `RetentionPeriod`

## Migration from `RingBufferAuditStore`

Drop-in replacement at registration. The in-memory ring is lost (no migration path — those entries were ephemeral by design). Going forward all entries hit the SQLite file.

```csharp
// Before
services.AddAISentinel(opts => { });
// After
services.AddAISentinel(opts => { });
services.AddSentinelSqliteStore(opts => opts.DatabasePath = "/var/lib/ai-sentinel/audit.db");
```

`AI.Sentinel.Sqlite` registration is idempotent and last-wins — calling it more than once just updates the configuration; the framework respects the most recent registration.

## Combining with forwarders

SQLite is the local **store**. You can layer **forwarders** on top — every entry written to SQLite is also handed to every forwarder:

```csharp
services.AddSentinelSqliteStore(opts => /* ... */);             // local source of truth
services.AddSentinelNdjsonFileForwarder(opts => /* ... */);     // tail with grep / jq
services.AddSentinelAzureSentinelForwarder(opts => /* ... */);  // central SIEM
```

This is the recommended production pattern: durable local store + at least one fan-out destination.

## Next: [Azure Sentinel](./azure-sentinel) — direct push to Logs Ingestion API
