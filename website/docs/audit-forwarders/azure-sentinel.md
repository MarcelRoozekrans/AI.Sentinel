---
sidebar_position: 4
title: Azure Sentinel
---

# Azure Sentinel forwarder

`AI.Sentinel.AzureSentinel` ships `AzureSentinelAuditForwarder` — direct push to the Azure Monitor **Logs Ingestion API**, the modern replacement for the deprecated HTTP Data Collector API. Routes every audit entry to a Custom Log table in your Log Analytics workspace.

Auto-wrapped in `BufferingAuditForwarder<T>` (batch=100, interval=5s, channel capacity=10000) — per-entry HTTP roundtrips would cap throughput well below what AI.Sentinel can produce.

## Wire it up

```bash
dotnet add package AI.Sentinel.AzureSentinel
```

```csharp
services.AddAISentinel(opts => /* ... */);
services.AddSentinelAzureSentinelForwarder(opts =>
{
    opts.DcrEndpoint    = new Uri("https://my-dce.westus2.ingest.monitor.azure.com");
    opts.DcrImmutableId = "dcr-abc123def456";
    opts.StreamName     = "Custom-AISentinelAudit_CL";
    // opts.Credential default = new DefaultAzureCredential()
});
```

## Required Azure setup

This forwarder targets the Logs Ingestion API, which requires three Azure resources configured in your subscription before it can send entries:

1. **Log Analytics workspace** — where audit entries land. Existing or new.
2. **Data Collection Endpoint (DCE)** — the regional ingestion endpoint. The `DcrEndpoint` URI in the config.
3. **Data Collection Rule (DCR)** — defines the custom-table schema and routes entries from the DCE to the workspace. The `DcrImmutableId` in the config.

Plus a **custom table** in the workspace with the right column schema. The default `StreamName` is `Custom-AISentinelAudit_CL` (the `_CL` suffix marks it as Custom Log).

The DCR's stream definition must include columns:

| Column | Type | Maps from |
|---|---|---|
| `TimeGenerated` | `datetime` | `AuditEntry.Timestamp` |
| `Id` | `string` | `AuditEntry.Id` |
| `Hash` | `string` | `AuditEntry.Hash` |
| `PreviousHash` | `string` | `AuditEntry.PreviousHash` |
| `Severity` | `string` | `AuditEntry.Severity` enum name |
| `DetectorId` | `string` | `AuditEntry.DetectorId` |
| `Summary` | `string` | `AuditEntry.Summary` |

A reference DCR template is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). The Microsoft docs for [creating a DCR](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal) walk through the portal setup.

## Authentication

Default is `DefaultAzureCredential` — the standard Azure SDK chained credential. In production, this typically resolves to:

- **Managed Identity** (recommended) — assign the identity the `Monitoring Metrics Publisher` role on the DCR
- **Service Principal** — `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET` env vars

For local development, `az login` works (interactive browser credential).

To override:

```csharp
services.AddSentinelAzureSentinelForwarder(opts =>
{
    opts.Credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    /* ... rest of config ... */
});
```

## Buffering and backpressure

Audit entries flow into a bounded `Channel<AuditEntry>` (capacity=10000 by default) and a background pump batches them every 5 seconds (or when the batch hits 100 entries). The pump POSTs each batch as a single HTTP call to the Logs Ingestion API.

When the channel is full (sustained SIEM downtime + high traffic):

- New entries are dropped (oldest preserved — channel mode is `BoundedChannelFullMode.DropWrite`)
- Drop counter `audit.forward.dropped` increments — exposed via OTel metrics
- Stderr log fires with rate limiting (once per minute, not per entry)

This is intentional. AI.Sentinel is in your request path. If Sentinel/Azure Monitor is down for an hour, you don't want every chat request to hang waiting on it. For guaranteed delivery, the [transactional outbox](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) pattern is on the backlog.

## Configuring buffering

The buffer settings are auto-applied in v1 (batch=100, interval=5s, channel=10000). Per-registration overrides via `.WithBuffering(maxBatch, maxInterval)` are on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md).

If your traffic shape needs different defaults today, you can wrap your own `BufferingAuditForwarder<AzureSentinelAuditForwarder>` and register that:

```csharp
services.AddSingleton<IAuditForwarder>(sp =>
{
    var inner = new AzureSentinelAuditForwarder(/* ... */);
    return new BufferingAuditForwarder<AzureSentinelAuditForwarder>(
        inner,
        maxBatchSize: 50,
        maxInterval: TimeSpan.FromSeconds(2),
        channelCapacity: 5000);
});
```

This bypasses the auto-wrapping. Use it when you need tighter latency or smaller batch sizes for low-volume deployments.

## Cost

Logs Ingestion API pricing is per GB ingested + per GB retained. AI.Sentinel audit entries are small (typically 200–500 bytes each):

- 1 million entries / month ≈ 200–500 MB ingested
- ~$2–5 / month at standard pricing

For high-traffic deployments, consider:

- Filtering by severity at the forwarder layer (don't ship `Severity.None` Clean entries — they're the majority)
- A custom transformation in the DCR to drop unhelpful columns
- A retention period shorter than the workspace default

## What you can do once data is in Sentinel

Standard Log Analytics + Sentinel features apply:

- **KQL queries** — `AISentinelAudit_CL | where Severity_s == "High" and TimeGenerated > ago(1h)`
- **Workbooks** — pre-built dashboards with KQL data sources
- **Analytics rules** — alert when AI.Sentinel detects N High+ events from a single SessionId in 5 min
- **Hunting queries** — proactive search across the audit history
- **Incident workflows** — auto-create Sentinel incidents on certain detector IDs (PII leakage, credential exposure)

Sample KQL queries are on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) for v1.1.

## Failure modes

| Failure | What happens |
|---|---|
| DCR endpoint unreachable | Buffered entries queue up; channel eventually fills, drops start |
| Auth fails (managed identity not granted role) | First batch fails, exception logged, entries dropped, retries on next batch |
| DCR schema mismatch | All batches fail with 400; entries dropped; investigate via stderr log |
| Custom table doesn't exist | Same — 400 / 404 from API, drops with diagnostic |

The forwarder doesn't retry indefinitely. If batches keep failing, drops accumulate. Check the `audit.forward.dropped` counter to detect chronic forwarding failures.

## Live integration test

A live integration test that exercises the full Logs Ingestion API round-trip (CI-secret-gated) is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). Today, end-to-end testing requires manually setting up a DCR + workspace and pointing a dev instance at it.

## When to use this forwarder

Best fit when:

- Your org already runs on Azure and uses Sentinel as primary SIEM
- You want native KQL + Sentinel hunting / analytics on AI.Sentinel data
- You're OK with regional ingestion endpoints (DCEs are regional)

Less ideal when:

- You're SIEM-agnostic and want vendor-neutrality — use [OpenTelemetry](./opentelemetry) instead
- You want guaranteed delivery for compliance — pair with a local persistent store (SQLite) for durability while waiting for upstream

## Next: [OpenTelemetry](./opentelemetry) — vendor-neutral via OTel collector
