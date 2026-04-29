---
sidebar_position: 4
title: Audit store
---

# Audit store

`IAuditStore` is the append-only record of every detection. It's a singleton in DI, owned by the framework. Every pass through `DetectionPipeline` results in exactly one audit entry per call (firing or Clean both write entries — there's no skip).

## The contract

```csharp
public interface IAuditStore
{
    ValueTask AppendAsync(AuditEntry entry, CancellationToken ct);
    IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct);
}
```

Append-only writes; query is a streaming async-enumerable cursor.

## `AuditEntry`

```csharp
public sealed record AuditEntry(
    string Id,                  // unique entry ID (Guid)
    DateTimeOffset Timestamp,
    string Hash,                // SHA-256 of (PreviousHash + Id + Timestamp + DetectorId + Severity + Summary)
    string? PreviousHash,       // null for the first entry, otherwise the previous entry's Hash
    Severity Severity,
    string DetectorId,
    string Summary);
```

Each entry includes the SHA-256 hash of the previous entry, forming a chain. **Tampering with any historical entry invalidates every subsequent hash** — making forensic verification straightforward.

## Hash chain verification

```csharp
async ValueTask<bool> VerifyChainAsync(IAuditStore store, CancellationToken ct)
{
    string? prev = null;
    await foreach (var entry in store.QueryAsync(new AuditQuery(), ct))
    {
        if (entry.PreviousHash != prev) return false;
        var expected = ComputeHash(prev, entry.Id, entry.Timestamp,
                                   entry.DetectorId, entry.Severity, entry.Summary);
        if (entry.Hash != expected) return false;
        prev = entry.Hash;
    }
    return true;
}
```

The `AI.Sentinel.Cli` `verify` subcommand (planned) does this for offline NDJSON exports. For SQLite, the `RunRetentionForTestingAsync` test hook exercises chain verification across retention sweeps.

## Built-in implementations

### `RingBufferAuditStore` (default)

Bounded in-memory ring buffer. Configured via `opts.AuditCapacity` (default 10,000 entries). When the buffer fills, oldest entries are dropped — by design, this is operational-monitoring data not long-term retention.

```csharp
services.AddAISentinel(opts =>
{
    opts.AuditCapacity = 50_000;  // larger ring for higher-volume hosts
});
```

Per-call cost: ~5 µs append, ~50 µs to enumerate via `QueryAsync`. Allocation-free on the append path (entries are reused).

### `SqliteAuditStore` (`AI.Sentinel.Sqlite`)

Persistent single-file SQLite database. Hash-chain integrity preserved across process restarts. Time-based retention sweep.

```csharp
// dotnet add package AI.Sentinel.Sqlite
services.AddSentinelSqliteAuditStore(new SqliteAuditStoreOptions
{
    DatabasePath = "/var/lib/ai-sentinel/audit.db",
    RetentionPeriod = TimeSpan.FromDays(90),
    RetentionSweepInterval = TimeSpan.FromHours(1),
});
```

Schema is auto-created on first use. WAL journal mode for concurrent readers. Indexed on `(Timestamp, Severity, DetectorId)` for query performance.

Per-call cost: ~100–500 µs append on local SSD. Slower than the ring buffer but durable.

See [SQLite audit store](../audit-forwarders/sqlite) for retention tuning, multi-instance considerations, and the schema details.

## Retention strategies

| Strategy | Where |
|---|---|
| **Bounded buffer** (drop oldest) | `RingBufferAuditStore.AuditCapacity` |
| **Time-based sweep** (delete older than N days) | `SqliteAuditStoreOptions.RetentionPeriod` |
| **Size-based cap** | Not yet — [backlog item](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) for `MaxDatabaseSizeBytes` on SQLite |
| **External SIEM retention** | Forward via [audit forwarders](../audit-forwarders/overview); your SIEM owns retention |

## Query API

`AuditQuery` filters:

```csharp
public sealed record AuditQuery(
    Severity? MinSeverity = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int PageSize = 1000);
```

```csharp
// Stream every High+ entry from the last hour
await foreach (var entry in store.QueryAsync(
    new AuditQuery(MinSeverity: Severity.High,
                   From: DateTimeOffset.UtcNow.AddHours(-1)),
    ct))
{
    Console.WriteLine($"{entry.Timestamp:o} {entry.DetectorId} {entry.Severity} — {entry.Summary}");
}
```

`QueryAsync` returns an `IAsyncEnumerable` so you can stream millions of entries without loading them into memory.

## Audit + intervention are decoupled

Every action the [intervention engine](./intervention-engine) takes — including `PassThrough` — appends an audit entry. Quarantining doesn't suppress audit. Logging doesn't add a *second* audit entry (the audit store *is* the durable record; the logger is the human-readable dupe).

This decoupling matters for forensic investigation: even if you set everything to `PassThrough` during initial rollout, the audit trail is complete.

## Forwarders fan out

After `IAuditStore.AppendAsync` writes, every registered `IAuditForwarder` fires off the same entry to its destination — Azure Sentinel, OpenTelemetry, NDJSON file, etc. Forwarders are async fire-and-forget — a forwarder failure doesn't fail the audit append. See [Audit forwarders](../audit-forwarders/overview) for the destination options.

## Custom audit stores

`IAuditStore` is the contract. To wire a Postgres-backed store, an EventStore-backed store, or any other implementation:

```csharp
public sealed class MyCustomAuditStore : IAuditStore
{
    public ValueTask AppendAsync(AuditEntry entry, CancellationToken ct) { /* ... */ }
    public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) { /* ... */ }
}

services.AddSingleton<IAuditStore, MyCustomAuditStore>();  // before AddAISentinel
```

The framework respects the singleton you registered. `AI.Sentinel.Postgres` is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) for multi-instance deployments.

## Next: [Severity model](./severity-model)
