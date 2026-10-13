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
    ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct);
    IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct);
}
```

Append-only writes; query is a streaming async-enumerable cursor. `AppendAsync` returns the entry **as stored**, with `Hash` and `PreviousHash` filled in by the store. Forward that returned entry, not the one you passed in.

## `AuditEntry`

```csharp
public sealed record AuditEntry(
    string Id,                  // unique entry ID (Guid)
    DateTimeOffset Timestamp,
    string Hash,                // set by the store: SHA-256 over PreviousHash and every field below
    string? PreviousHash,       // set by the store: null for the first entry, otherwise the previous entry's Hash
    Severity Severity,
    string DetectorId,
    string Summary,
    string? PolicyCode = null,  // AUTHZ-DENY entries only
    string? SessionId = null);
```

The store links every entry it appends into a SHA-256 hash chain ([`AuditHashChain`](#hash-chain-verification)). An entry's `Hash` covers its own fields and the previous entry's hash, so **editing, inserting or deleting any entry breaks the link to the entry after it**. Callers pass `Hash: string.Empty, PreviousHash: null`; whatever they pass is replaced.

## Hash chain verification

```csharp
var result = await AuditHashChain.VerifyAsync(
    store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), ct), ct);

if (!result.IsIntact)
    Console.WriteLine($"Chain broken at entry {result.FirstBrokenEntryId} after {result.EntriesChecked} good entries");
```

`VerifyAsync` walks the entries oldest first and stops at the first one that fails. After an edit that is the edited entry; after a deletion it is the entry that follows the gap.

Verification starts from the oldest entry still present. When the ring buffer has evicted entries, or SQLite retention has deleted them, that entry's `PreviousHash` is returned as `result.AnchorHash`. A `null` anchor means the chain is complete from its first entry. SQLite keeps the chain head in its own table, so the chain continues, and the anchor stays non-null, even after retention has deleted every entry. Deleting entries from the *head* of the chain looks the same as retention, so record the anchor in a report and compare it with the next one to detect that.

The `AI.Sentinel.Cli` `verify` subcommand (planned) will do this for offline NDJSON exports.

:::note Upgrading from 2.x
Entries written before 3.0 are not chained, so a store that holds them fails verification at its first old entry. Verify from the upgrade onward with `new AuditQuery(From: upgradedAt, PageSize: int.MaxValue)`, where `upgradedAt` is when the upgraded process started: every old entry was written before that, and every new one after. The first new entry's `PreviousHash` is the last old entry's hash and becomes the anchor.

The SQLite store migrates to schema v4 on first open. Detection entries written before 3.0 had `policy_code` set to `policy_denied` by a column default; the migration clears it, so only `AUTHZ-DENY` entries carry a policy code.
:::

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
services.AddSentinelSqliteStore(opts =>
{
    opts.DatabasePath = "/var/lib/ai-sentinel/audit.db";
    opts.RetentionPeriod = TimeSpan.FromDays(90);
    opts.RetentionSweepInterval = TimeSpan.FromHours(1);
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
| **Size-based cap** (delete oldest until under N bytes) | `SqliteAuditStoreOptions.MaxDatabaseSizeBytes` |
| **External SIEM retention** | Forward via [audit forwarders](../audit-forwarders/overview); your SIEM owns retention |

## Query API

`AuditQuery` filters:

```csharp
public sealed record AuditQuery(
    Severity? MinSeverity = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int PageSize = 200,
    bool Reverse = false,       // newest first
    string? SessionId = null);
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

After `IAuditStore.AppendAsync` writes, every registered `IAuditForwarder` receives the entry as stored, chain hashes included, and sends it to its destination — Azure Sentinel, OpenTelemetry, NDJSON file, etc. Forwarders are async fire-and-forget — a forwarder failure doesn't fail the audit append. See [Audit forwarders](../audit-forwarders/overview) for the destination options.

## Custom audit stores

`IAuditStore` is the contract. To wire a Postgres-backed store, an EventStore-backed store, or any other implementation:

```csharp
public sealed class MyCustomAuditStore : IAuditStore
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private string? _lastHash;   // load the newest stored Hash at startup so the chain continues

    public async ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            // Link under the write lock, so concurrent appends cannot fork the chain.
            var linked = AuditHashChain.Link(entry, _lastHash);
            /* persist linked */
            _lastHash = linked.Hash;
            return linked;
        }
        finally { _writeLock.Release(); }
    }

    public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) { /* oldest first unless query.Reverse */ }
}

services.AddSingleton<IAuditStore, MyCustomAuditStore>();  // before AddAISentinel
```

The framework respects the singleton you registered. `AI.Sentinel.Postgres` is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) for multi-instance deployments.

## Next: [Severity model](./severity-model)
