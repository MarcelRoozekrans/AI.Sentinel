---
sidebar_position: 3
title: SQLite
---

# SQLite audit store

`AI.Sentinel.Sqlite` ships `SqliteAuditStore` — a persistent `IAuditStore` backed by a single-file SQLite database. Hash-chain integrity preserved across process restarts. Time-based retention sweep. WAL journal mode for concurrent readers. Several processes can write to one file.

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

The database file is created at startup if it doesn't exist. Schema is auto-migrated. WAL journal mode is enabled so readers never block. Several processes may write to the same file at once: each append takes the database write lock, re-reads the chain head inside it and chains onto whatever the other processes wrote, so the hash chain stays intact. This is how `sentinel-hook`, `sentinel-copilot-hook` and `sentinel-mcp` share one file. It is a feature for processes on one machine, not for a network share.

## Options for short-lived writers

A process that opens the file, writes a few entries and exits, such as a CLI hook, needs different defaults from a long-running app:

| Option | Default | Purpose |
|---|---|---|
| `BusyTimeout` | 30 seconds | How long a write waits for another process's write lock before failing with a `SqliteException`. Rounded up to whole seconds. The CLIs use 2 seconds so a busy file never stalls an agent |
| `EnforceSizeCapOnOpen` | `false` | Apply `MaxDatabaseSizeBytes` once while opening, instead of waiting for the sweep timer, which a short-lived process never reaches |
| `VacuumAfterTrim` | `true` | End a size trim with `VACUUM` and a WAL truncate so the file shrinks. Set `false` for short-lived writers: `VACUUM` holds the cross-process write lock for a long time. Freed pages are reused, so the file stops growing at about the cap instead of shrinking |

```csharp
opts.BusyTimeout = TimeSpan.FromSeconds(2);
opts.MaxDatabaseSizeBytes = 100L * 1024 * 1024;
opts.EnforceSizeCapOnOpen = true;
opts.VacuumAfterTrim = false;
```

## Schema

```sql
CREATE TABLE IF NOT EXISTS audit_entries (
    id            TEXT PRIMARY KEY,
    timestamp     INTEGER NOT NULL,    -- Unix milliseconds
    severity      INTEGER NOT NULL,    -- enum value
    detector_id   TEXT NOT NULL,
    hash          TEXT NOT NULL,
    previous_hash TEXT,
    summary       TEXT NOT NULL,
    sequence      INTEGER NOT NULL,    -- append order, the order the hash chain follows
    policy_code   TEXT,                -- AUTHZ-DENY entries only
    session_id    TEXT,
    source        TEXT                 -- claude-code, copilot, mcp; NULL for in-process apps
);

CREATE INDEX idx_audit_timestamp ON audit_entries (timestamp);
CREATE INDEX idx_audit_detector  ON audit_entries (detector_id);
CREATE INDEX idx_audit_severity  ON audit_entries (severity);
CREATE INDEX idx_audit_sequence  ON audit_entries (sequence);
CREATE INDEX idx_audit_session   ON audit_entries (session_id);
```

A second table, `audit_chain_head`, holds one row with the hash of the last appended entry, so the chain continues even after retention deletes every entry.

Indexes optimize the common `AuditQuery` filter combinations (time range, min severity, detector ID, session). The schema is version 5; older files are migrated when opened, and two processes opening an old file at the same time migrate it once. `AuditQuery.Source` filters on the `source` column.

## Performance

- Append: ~100–500 µs on local SSD (single-row INSERT in WAL mode)
- Query: streams via `IAsyncEnumerable<AuditEntry>` — millions of rows iterable without loading them
- Concurrent readers safe (WAL); writes are serialized in-process behind a `SemaphoreSlim` and across processes by the SQLite write lock

The pipeline cost of using SQLite over RingBuffer is the difference between &lt;5 µs (memory) and ~100 µs (disk). For most chat workloads this is invisible — the LLM round-trip dominates by 4+ orders of magnitude.

## Hash chain across restarts

The store reloads the most recent `Hash` at startup so the next entry chains correctly. Tampering with the SQLite file (editing a row, deleting one, inserting one) breaks the chain at the tampered entry: either its own `hash` no longer matches its fields, or its `previous_hash` no longer matches the entry before it.

To verify a database file:

```csharp
var sqlite = sp.GetRequiredService<IAuditStore>();
var result = await AuditHashChain.VerifyAsync(
    sqlite.QueryAsync(new AuditQuery(PageSize: int.MaxValue), ct), ct);

if (!result.IsIntact)
    throw new InvalidOperationException($"Audit chain broken at entry {result.FirstBrokenEntryId}");
```

Retention deletes the oldest rows, so after a sweep the chain verifies from the oldest remaining entry and `result.AnchorHash` holds the hash of the last deleted one. See [Hash chain verification](../core-concepts/audit-store#hash-chain-verification) for what the anchor tells you, and for verifying a database that still holds entries from before 3.0.

`sentinel dashboard --db <path>` from the `AI.Sentinel.Cli` tool runs the same check when it starts and prints `Audit chain intact: N entries` or `Audit chain broken at entry {id}`. A standalone `verify` command is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md).

## Retention

Two retention strategies, which can be combined:

### Time-based sweep (built-in)

```csharp
opts.RetentionPeriod = TimeSpan.FromDays(90);
opts.RetentionSweepInterval = TimeSpan.FromHours(1);
```

A background timer fires every `RetentionSweepInterval` and deletes entries older than `RetentionPeriod`, oldest first in append order. It stops at the first entry that is still within the period, so an expired entry that was appended after a younger one stays until that younger one expires too. Deleting by timestamp alone would cut the hash chain in the middle. For the same reason, an entry whose `Timestamp` lies in the future, because a caller set it or the clock stepped back, holds up time-based deletion until that time has passed; `MaxDatabaseSizeBytes` still applies meanwhile. Default sweep interval is 1 hour; default retention period is `null` (no expiry — keep forever).

The sweep is best-effort. It runs while the process is alive; if the process restarts, the timer resets. Old entries persist across restarts until the next sweep tick fires.

Long retention periods are fine — SQLite handles billions of rows without performance degradation given proper indexes (which the schema provides).

### Size-based cap (built-in)

```csharp
opts.MaxDatabaseSizeBytes = 512L * 1024 * 1024; // 512 MB
```

On the same sweep timer, the store deletes the oldest entries in batches of 10% (at least 100) and runs `VACUUM` until the file is under the cap. Both strategies remove entries from the head of the hash chain only, so the remaining chain still verifies.

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

Not supported in v1. Several processes on one machine can share a file, but SQLite isn't designed for multi-writer access across machines or over a network file system. For multi-instance shared storage, use a forwarder to push entries into a central system (Postgres-backed audit store is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) for that scenario).

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
