---
sidebar_position: 1
title: Overview
---

# Audit forwarders overview

AI.Sentinel separates audit **storage** from audit **forwarding**:

| Capability | Interface | Singular / plural | Purpose |
|---|---|:---:|---|
| **Storage** | `IAuditStore` | one | Source of truth. Queryable. Hash-chain integrity. Survives across the process lifetime (or longer with SQLite). |
| **Forwarding** | `IAuditForwarder` | many | Fire-and-forget mirrors of every audit entry to external systems. Never blocks. |

The default is in-memory `RingBufferAuditStore` + zero forwarders — no extra dependencies, no out-of-process services. You opt into persistence and fan-out independently.

## Built-in implementations

| What | Package | Capability |
|---|---|---|
| `RingBufferAuditStore` | `AI.Sentinel` (core) | Default in-memory store; bounded LRU, lost on restart |
| [`SqliteAuditStore`](./sqlite) | `AI.Sentinel.Sqlite` | Persistent local store; survives restarts |
| [`NdjsonFileAuditForwarder`](./ndjson) | `AI.Sentinel` (core) | Append-only NDJSON file; ship via Filebeat/Vector/Fluent Bit |
| [`AzureSentinelAuditForwarder`](./azure-sentinel) | `AI.Sentinel.AzureSentinel` | Direct push to Azure Monitor Logs Ingestion API |
| [`OpenTelemetryAuditForwarder`](./opentelemetry) | `AI.Sentinel.OpenTelemetry` | Vendor-neutral OTel log records; routes anywhere your OTel collector goes |

## How storage and forwarders relate

When the pipeline emits an audit entry, the framework calls:

```
1. IAuditStore.AppendAsync(entry, ct)
2. for each IAuditForwarder: forwarder.SendAsync(entry, ct)  // fire-and-forget
```

Step 1 is the durable record — your queryable source of truth. Step 2 is the fan-out — every registered forwarder gets a copy. A forwarder failure doesn't fail the audit append; failures swallow + log to stderr + increment a metric counter.

## Picking a configuration

| Scenario | What to register |
|---|---|
| Quick local development | Defaults (RingBuffer + no forwarders). Use the dashboard at `app.UseAISentinel("/ai-sentinel")` for live view. |
| Single-instance production | `SqliteAuditStore` for durable local audit + dashboard for ops |
| Multi-instance production with central ops | `SqliteAuditStore` per instance + `AzureSentinelAuditForwarder` or `OpenTelemetryAuditForwarder` for unified central view |
| Compliance + SIEM-driven security | `SqliteAuditStore` (local hash-chain integrity) + `AzureSentinelAuditForwarder` (centralized retention) |
| File-based pipelines (Vector/Fluent Bit/Filebeat) | `NdjsonFileAuditForwarder` (zero deps) — your existing log shipper handles the rest |
| Vendor-neutral observability stack | `OpenTelemetryAuditForwarder` — picks up wherever your OTel collector routes |

## Forwarder reliability

Forwarders are **fire-and-forget**. They never block the chat-client pipeline and never throw exceptions back into your app. The contract:

- `SendAsync` returns `ValueTask` — typically completes synchronously on the hot path (handing to a channel or in-memory queue)
- Failures (network errors, SIEM unavailable, etc.) swallow the exception, log to stderr, and increment `audit.forward.dropped`
- Buffered forwarders drop oldest entries on backpressure — protecting the hot path is more important than guaranteed delivery

This is intentional. AI.Sentinel is in your request path; if a SIEM goes down, you don't want every chat request to fail. For audit entries you can't afford to lose, the durable layer is `IAuditStore` (always synchronous, always blocking the pipeline). Forwarders are for *near-real-time visibility*, not durable transport.

For guaranteed delivery to external SIEMs, the [transactional outbox pattern](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) is on the backlog — would integrate with `ZeroAlloc.Outbox` for production-grade reliability.

## Buffering decorator

Some forwarders need batching to avoid per-entry HTTP roundtrips. `BufferingAuditForwarder<T>` is the wrapper:

| Forwarder | Auto-buffered |
|---|:---:|
| `NdjsonFileAuditForwarder` | — (file append is already fast) |
| `AzureSentinelAuditForwarder` | ✓ (default: batch=100, interval=5s, channel=10000) |
| `OpenTelemetryAuditForwarder` | — (OTel SDK does its own `BatchLogRecordExportProcessor` batching) |

Buffered forwarders drop entries when the channel overflows (e.g., SIEM is down for an extended period). The drop counter `audit.forward.dropped` is exposed via OpenTelemetry metrics for monitoring.

## Multiple forwarders

You can register multiple forwarders — every audit entry goes to all of them:

```csharp
services.AddAISentinel(opts => /* ... */);
services.AddSentinelSqliteStore(opts => opts.DatabasePath = "/var/lib/ai-sentinel/audit.db");
services.AddSentinelNdjsonFileForwarder(opts => opts.FilePath = "/var/log/ai-sentinel/audit.ndjson");
services.AddSentinelAzureSentinelForwarder(opts =>
{
    opts.DcrEndpoint = new Uri("https://...");
    opts.DcrImmutableId = "dcr-abc123";
    opts.StreamName = "Custom-AISentinelAudit_CL";
});
```

Common pattern: SQLite for local source-of-truth + Azure Sentinel (or OTel) for central visibility. Belt-and-suspenders.

## Hash chain across forwarders

Every audit entry carries `Hash` and `PreviousHash`. These come from the **store** (the durable record). Forwarders ship the same hashes downstream — so a SIEM-side verifier can also detect tampering. The hash chain is **store-relative**; if you have multiple stores (e.g., SQLite locally + RingBuffer in dev), they each have their own chain.

For multi-instance deployments where a central SIEM aggregates from all instances, the hash chains will be per-instance. That's fine — the chain provides *integrity*, not *ordering across instances*. Cross-instance ordering uses Timestamp and instance ID.

## Where to next

- [NDJSON file](./ndjson) — zero-dependency file forwarder
- [SQLite](./sqlite) — persistent local store with retention
- [Azure Sentinel](./azure-sentinel) — direct push to Logs Ingestion API
- [OpenTelemetry](./opentelemetry) — vendor-neutral via OTel collector
