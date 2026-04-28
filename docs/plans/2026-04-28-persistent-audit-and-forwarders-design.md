# Persistent Audit Store + External Forwarders Design

**Date:** 2026-04-28

---

## Problem

Today's `IAuditStore` has one implementation: `RingBufferAuditStore` (in-memory, capped at 1024 entries by default). This solves the dashboard live-feed use case but blocks two real enterprise requirements:

1. **Persistence across restarts.** A long-running proxy that crashes loses every audit entry not yet shipped elsewhere. Forensics, compliance audits, and post-incident review all need durable storage.
2. **Centralised SIEM/observability.** Operators running AI.Sentinel inside an enterprise environment need audit data to reach Azure Sentinel / Splunk / Datadog / Elastic. Today the only export path is "ssh into the box and read the ring buffer" or the unstructured stderr stream.

The existing `IAlertSink` covers real-time threat *notifications* (high-severity events to a webhook) but not the bulk audit stream (every entry, including clean events, hash-chained, queryable).

## Goal

Ship two related capabilities as v1 of an enterprise audit story:

1. **`SqliteAuditStore`** — a persistent, queryable `IAuditStore` implementation. Single-file, embedded, zero infrastructure overhead. Replaces the ring buffer for users who care about durability.
2. **`IAuditForwarder` + three reference implementations** — a new abstraction that ships every audit entry out to one or more external systems. Reference impls: `NdjsonFileAuditForwarder` (zero-dep, universal via Filebeat/Vector), `AzureSentinelAuditForwarder` (Microsoft Cloud direct), `OpenTelemetryAuditForwarder` (vendor-neutral — Splunk, Datadog, Elastic, etc. via OTel collector).

Storage and forwarding are deliberately **separate concerns** with separate interfaces and DI registrations. Existing users (no new registration) see no behaviour change — this is a strict superset.

---

## Architecture

```
SentinelPipeline.AppendAuditAsync(entry)
       │
       ├──► IAuditStore.AppendAsync(entry, ct)           ← single, source of truth, awaited
       │       (RingBufferAuditStore [default] / SqliteAuditStore)
       │
       └──► foreach forwarder in IEnumerable<IAuditForwarder>
                 fire-and-forget: forwarder.SendAsync([entry], ct)
                 (NdjsonFileAuditForwarder direct)
                 (BufferingAuditForwarder<AzureSentinelAuditForwarder> wrapped)
                 (BufferingAuditForwarder<OpenTelemetryAuditForwarder> wrapped — but NOT used; OTel batches itself)
```

**Why two interfaces, not one:**

- Storage and forwarding have different semantics: storage is awaited (an audit append failure is a problem worth surfacing); forwarders are best-effort (a SIEM outage must never block the proxy).
- Storage is singular ("where does the source-of-truth audit log live?"); forwarders are plural ("which external systems should mirror the stream?"). DI shape reflects this — `IAuditStore` is registered once, `IEnumerable<IAuditForwarder>` collects all forwarders.
- Failure handling differs: store throws / surfaces; forwarders swallow + log + counter.

**Source-of-truth schema** is the existing `AuditEntry` record. Each forwarder transforms it to its target system's idiom — no new "common log schema" type. Keeps forwarders honest about what they're shipping.

---

## Interfaces

```csharp
// EXISTING — unchanged
public interface IAuditStore
{
    ValueTask AppendAsync(AuditEntry entry, CancellationToken ct);
    IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct);
}

// NEW
public interface IAuditForwarder
{
    /// <summary>Ships a batch of audit entries to an external system. Implementations
    /// MUST NOT throw — failures are swallowed and surfaced via stderr / metrics.</summary>
    ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct);
}
```

**Why `IReadOnlyList<AuditEntry>` even for single entries?** Forwarders wrapped with `BufferingAuditForwarder` receive real batches (10-1000 entries). Forwarders without buffering get single-entry lists. One signature handles both — no overload soup.

---

## Component: `SqliteAuditStore` (new package `AI.Sentinel.Sqlite`)

Dependency: `Microsoft.Data.Sqlite`.

### Schema

```sql
CREATE TABLE IF NOT EXISTS audit_entries (
    id            TEXT PRIMARY KEY,
    timestamp     INTEGER NOT NULL,           -- UnixEpoch ms
    severity      INTEGER NOT NULL,           -- enum value
    detector_id   TEXT NOT NULL,
    hash          TEXT NOT NULL,
    previous_hash TEXT,
    summary       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_detector  ON audit_entries (detector_id);
CREATE INDEX IF NOT EXISTS idx_audit_severity  ON audit_entries (severity);
```

Columns mirror `AuditEntry` 1:1. No JSON blobs.

### Schema migration

`PRAGMA user_version` checked at startup; runs idempotent migrations 0 → current. v1 ships at `user_version = 1`. Future column additions (`caller_id` when PIM ships, `tool_name` when audit gets richer) are append-only `ALTER TABLE` migrations.

### Hash chain across restart

The hash chain *survives* a restart. On first append after construction, the store reads the most-recent row's `hash` and uses it as `previousHash` for the new entry. Tamper-evidence guarantee end-to-end.

### Concurrency + durability

- Single `SqliteConnection` opened in the constructor (`Pooling=False`), held for the store's lifetime.
- Concurrent writers serialise via `SemaphoreSlim(1, 1)` inside the store.
- `PRAGMA journal_mode = WAL` — concurrent reads while writer is active.
- `PRAGMA synchronous = NORMAL` — durable on OS crash, not on power loss. Acceptable for audit log; users who want stricter override via `RawConnectionStringSuffix`.

### Configuration

```csharp
public sealed class SqliteAuditStoreOptions
{
    /// <summary>Path to the SQLite database file. Created if missing.</summary>
    public string DatabasePath { get; set; } = "audit.db";

    /// <summary>Optional retention — DELETE rows older than this. Null = retain forever.</summary>
    public TimeSpan? RetentionPeriod { get; set; }
}
```

`RetentionPeriod` runs via a background `Timer` once per hour: `DELETE FROM audit_entries WHERE timestamp < ?`.

### Out of scope (deferred to backlog)

- `MaxDatabaseSizeBytes` cap (size-based retention)
- File rotation
- Postgres backend (`AI.Sentinel.Postgres`)

---

## Component: `NdjsonFileAuditForwarder` (in `AI.Sentinel` core)

Zero new dependencies. Lives in core because it's the universally-useful base case.

### Behaviour

- Opens the file in append mode at construction; holds the `FileStream` for the forwarder's lifetime.
- `SendAsync` writes one `JsonSerializer.Serialize(entry, source-gen-context)` line per entry + `\n`.
- Flushes after every batch.
- Concurrency: `SemaphoreSlim(1, 1)` for line-atomic writes.
- **No buffering decorator wrapping** — direct file append is already fast (microseconds). Wrapping would add latency without throughput benefit.

### Configuration

```csharp
public sealed class NdjsonFileAuditForwarderOptions
{
    /// <summary>Path to the NDJSON file. Appended to; created if missing.</summary>
    public string FilePath { get; set; } = "audit.ndjson";
}
```

### Out of scope (deferred to backlog)

- File rotation (logrotate / Vector handle this externally)

---

## Component: `AzureSentinelAuditForwarder` (new package `AI.Sentinel.AzureSentinel`)

Dependency: `Azure.Monitor.Ingestion`.

### Behaviour

Wraps `LogsIngestionClient`. `SendAsync(batch, ct)` calls `client.UploadAsync(DcrImmutableId, StreamName, batch, ct)`. The Azure SDK serialises via `System.Text.Json` — we register a source-gen context for AOT compatibility.

### Auth

Default `DefaultAzureCredential` — picks up Azure CLI / managed identity / env vars in priority order. Power users supply a specific `TokenCredential` (`WorkloadIdentityCredential` for AKS, etc.).

### Failure handling

`RequestFailedException` from the SDK → swallowed, stderr-logged, drop counter incremented. Same posture as `WebhookAlertSink`.

### Auto-buffering

`AddSentinelAzureSentinelForwarder` automatically wraps with `BufferingAuditForwarder` (defaults: batch=100, interval=5s). Per-entry HTTP roundtrips to Sentinel (~50-200ms each) are unworkable.

### Configuration

```csharp
public sealed class AzureSentinelAuditForwarderOptions
{
    public Uri DcrEndpoint { get; set; } = null!;
    public string DcrImmutableId { get; set; } = null!;
    public string StreamName { get; set; } = null!;
    public TokenCredential? Credential { get; set; }   // default DefaultAzureCredential
}
```

### Operator setup

Users must create a DCR + custom table in their Log Analytics workspace before this works. README links to Microsoft's setup docs.

---

## Component: `OpenTelemetryAuditForwarder` (new package `AI.Sentinel.OpenTelemetry`)

Dependency: `OpenTelemetry.Logs`.

### Behaviour

Holds an `ILogger` from DI / supplied factory. `SendAsync(batch, ct)` iterates the batch and emits one `LogRecord` per entry via `_logger.Log(level, ...)`. The OTel SDK's `BatchLogRecordExportProcessor` (wired by the user via standard `OpenTelemetryBuilder.WithLogging(...)`) handles batching, exporter routing, and retry — we don't reimplement.

### Severity mapping

| `AuditEntry.Severity` | OTel `LogLevel` |
|---|---|
| Critical | Critical |
| High | Error |
| Medium | Warning |
| Low | Information |
| None | Debug |

### Field mapping (semantic conventions)

- `LogRecord.Body` = `entry.Summary`
- `Attributes["audit.id"]` = `entry.Id`
- `Attributes["audit.detector_id"]` = `entry.DetectorId`
- `Attributes["audit.severity"]` = `entry.Severity` (enum string)
- `Attributes["audit.hash"]` = `entry.Hash`
- `Attributes["audit.previous_hash"]` = `entry.PreviousHash`
- `Attributes["audit.timestamp"]` = `entry.Timestamp` (ISO-8601)

### No auto-buffering

OTel SDK already batches. Wrapping with `BufferingAuditForwarder` would double-buffer. XML doc on `AddSentinelOpenTelemetryForwarder` explicitly notes this.

### Configuration

```csharp
public sealed class OpenTelemetryAuditForwarderOptions
{
    public ILoggerFactory? LoggerFactory { get; set; }
    public string CategoryName { get; set; } = "AI.Sentinel.Audit";
}
```

---

## Component: `BufferingAuditForwarder<TInner>` (in `AI.Sentinel` core)

Decorator that wraps any `IAuditForwarder`. ~80 LOC.

### Internals

- `Channel<AuditEntry>` (bounded, default capacity 10 000).
- Background `Task` reader pulls from channel, accumulates a `List<AuditEntry>`, calls `inner.SendAsync(batch)` when **either** `batch.Count >= MaxBatchSize` **or** elapsed time since last flush ≥ `MaxFlushInterval`.
- `SendAsync(batch)` from the pipeline writes via `TryWrite` (non-blocking). On full channel: drop, increment `audit.forward.dropped` counter, log to stderr at most once per second (rate-limited).
- `IAsyncDisposable` — flushes pending batch on dispose.

### Configuration

```csharp
public sealed class BufferingAuditForwarderOptions
{
    public int MaxBatchSize     { get; set; } = 100;
    public TimeSpan MaxFlushInterval { get; set; } = TimeSpan.FromSeconds(5);
    public int ChannelCapacity  { get; set; } = 10_000;
}
```

### Why drop, not block

Back-pressure-on-SIEM-outage stops the LLM proxy. Drop-with-stderr-log + a `audit.forward.dropped` counter is the correct enterprise default — operators get visibility via metrics, the proxy keeps serving traffic. Users who want stricter behaviour can implement their own forwarder with `await channel.WriteAsync(...)` instead of `TryWrite`.

---

## DI Registration Shape

### Storage (singular — picks one)

```csharp
// Default if no store registered: RingBufferAuditStore (existing — no breakage)
services.AddAISentinel(opts => { ... });

// OR opt into SQLite (replaces the ring buffer):
services.AddAISentinel(opts => { ... });
services.AddSentinelSqliteStore(opts =>
{
    opts.DatabasePath    = "/var/lib/ai-sentinel/audit.db";
    opts.RetentionPeriod = TimeSpan.FromDays(90);
});
```

Last-registration-wins for `IAuditStore`. Documented on the extension's XML doc.

### Forwarders (zero-or-more)

```csharp
// NDJSON file — direct, no buffering needed
services.AddSentinelNdjsonFileForwarder(opts => opts.FilePath = "/var/log/sentinel.ndjson");

// Azure Sentinel — auto-wrapped with buffering
services.AddSentinelAzureSentinelForwarder(opts =>
{
    opts.DcrEndpoint    = new Uri("https://my-dce.westus2.ingest.monitor.azure.com");
    opts.DcrImmutableId = "dcr-abc123";
    opts.StreamName     = "Custom-AISentinelAudit_CL";
});
// Optional buffering override:
services.AddSentinelAzureSentinelForwarder(opts => { ... })
        .WithBuffering(maxBatch: 500, maxInterval: TimeSpan.FromSeconds(10));

// OpenTelemetry — relies on user's existing OTel logging pipeline
services.AddSentinelOpenTelemetryForwarder();
services.AddOpenTelemetry().WithLogging(b => b.AddOtlpExporter());
```

### `SentinelPipeline` constructor change

```csharp
public SentinelPipeline(
    IChatClient innerClient,
    IDetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options,
    IEnumerable<IAuditForwarder>? forwarders = null,   // NEW — optional, default empty
    ILogger<SentinelPipeline>? logger = null)
```

After every successful `auditStore.AppendAsync(entry)`:

```csharp
foreach (var forwarder in _forwarders)
{
    _ = forwarder.SendAsync([entry], ct);   // fire-and-forget
}
```

Empty default keeps existing users at zero overhead.

---

## Instrumentation

Via existing `ZeroAlloc.Telemetry` `[Instrument("ai.sentinel")]`:

- `audit.forward.batches` (counter) — per forwarder, batches sent
- `audit.forward.entries` (counter) — per forwarder, individual entries shipped
- `audit.forward.dropped` (counter) — buffering overflow drops
- `audit.forward.duration_ms` (histogram) — per forwarder

---

## Test Strategy

### `AI.Sentinel` core (`tests/AI.Sentinel.Tests/Audit/`)

| Component | Tests |
|---|---|
| `BufferingAuditForwarder<T>` | empty batch never flushes; size-threshold flush; interval-threshold flush; channel overflow drops + counter; dispose flushes pending; concurrent writes serialised; inner exception swallowed; rate-limited stderr log on overflow |
| `NdjsonFileAuditForwarder` | basic write; one line per entry; newline-in-summary escaped; append mode preserved; concurrent batches serialised |
| Pipeline integration | forwarder receives single-entry batch on every audit append; multiple forwarders all receive entry; one slow forwarder doesn't block others; empty `IEnumerable<IAuditForwarder>` works |

### `AI.Sentinel.Sqlite` (new test project)

| Test | What it proves |
|---|---|
| `Append_PersistsToFile_QueryReturnsAfterReopen` | Survives restart |
| `HashChain_PreviousHashLinksToLastEntryOnReopen` | Tamper-evidence end-to-end |
| `Query_FiltersBySeverityAndDetector` | Indexes used correctly |
| `Query_TimestampRange_ReturnsCorrectSlice` | Range scan correctness |
| `RetentionPeriod_DropsOldRowsAfterTimer` | Background cleanup works |
| `RetentionPeriod_Null_RetainsForever` | Default behaviour |
| `Schema_Version1_NewDatabaseInitialised` | Migration baseline |
| `ConcurrentAppends_AllPersisted_NoCorruption` | Lock correctness |

### `AI.Sentinel.AzureSentinel` (new test project)

Stub `LogsIngestionClient` (or hand-rolled stub matching MCP test infra pattern).

| Test | What it proves |
|---|---|
| `SendAsync_CallsUploadAsyncOnce_WithCorrectBatch` | Round-trip happy path |
| `SendAsync_RequestFailedException_Swallowed_LoggedToStderr_CounterIncremented` | Failure handling |
| `SendAsync_DefaultCredential_UsedWhenNotSupplied` | Auth default |
| `Options_MissingDcrEndpoint_ThrowsAtConstruction` | Config validation |

### `AI.Sentinel.OpenTelemetry` (new test project)

Uses `InMemoryExporter` to capture emitted log records.

| Test | What it proves |
|---|---|
| `SendAsync_EmitsOneLogRecordPerEntry` | Iteration correct |
| `SendAsync_SeverityCriticalMapsToLogLevelCritical` (and rest of mapping table) | Severity mapping |
| `SendAsync_AuditEntryFieldsLiftedAsAttributes` | Semantic conventions |
| `SendAsync_BodyEqualsSummary` | Body assignment |

### Explicitly NOT tested in v1
- Live Azure Sentinel ingestion (no SDL secrets in CI)
- Live OTel collector round-trip (would need integration env)
- SQLite under simulated disk-full / corruption scenarios
- Buffer drop behaviour under simulated GC pressure

---

## Backlog Updates

### Add (deferred items)

1. **`AI.Sentinel.Postgres`** — server-grade audit store for multi-instance deployments.
2. **`SplunkHecAuditForwarder`** — direct HEC endpoint (alternative to OTel-collector path).
3. **`GenericWebhookAuditForwarder`** — operator-defined POST endpoint with template payload.
4. **NDJSON file rotation** — in-process rotation by size or time window.
5. **`MaxDatabaseSizeBytes` cap on `SqliteAuditStore`** — alongside `RetentionPeriod` for defence in depth.
6. **Live integration test for `AzureSentinelAuditForwarder`** — gated on a CI secret with a real Sentinel workspace.
7. **Live OTel collector integration test** — Docker-Compose collector + verify round-trip.

### Remove (now shipped)

- The existing `Persistent audit store` line under "Architecture / Integration" — replaced by SQLite + design references for Postgres-as-followup.

---

## Estimated Scope

- 1 new interface (`IAuditForwarder`) + 1 buffering decorator in core (~150 LOC)
- 1 NDJSON forwarder in core (~80 LOC)
- 3 new packages (`AI.Sentinel.Sqlite`, `AI.Sentinel.AzureSentinel`, `AI.Sentinel.OpenTelemetry`) — each is a thin wrapper over the SDK + DI registration extension
- ~25-30 new tests across 4 test projects

Should land in 5-7 implementation tasks given the package boundaries.
