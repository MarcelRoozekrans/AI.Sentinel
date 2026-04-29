---
sidebar_position: 5
title: OpenTelemetry
---

# OpenTelemetry forwarder

`AI.Sentinel.OpenTelemetry` ships `OpenTelemetryAuditForwarder` — vendor-neutral. Audit entries become OTel log records routed through your existing OpenTelemetry pipeline to whatever backend you've configured (Splunk, Datadog, Elastic, New Relic, Loki, Grafana Cloud, Honeycomb, Lightstep, anywhere OTLP speaks).

Reuses your existing OTel logging configuration — no separate exporters, no new authentication, no new pipeline. Just adds AI.Sentinel as another producer of log records.

## Wire it up

```bash
dotnet add package AI.Sentinel.OpenTelemetry
```

```csharp
services.AddAISentinel(opts => /* ... */);
services.AddSentinelOpenTelemetryForwarder();

// Bring your own OTel logging pipeline
services.AddOpenTelemetry()
    .WithLogging(b => b.AddOtlpExporter(o =>
    {
        o.Endpoint = new Uri("https://otel-collector.example.com:4317");
        o.Protocol = OtlpExportProtocol.Grpc;
    }));
```

That's it. AI.Sentinel audit entries flow into the same logging pipeline your application logs use. The OTel SDK handles batching, retries, and protocol concerns.

## What gets emitted

Each `AuditEntry` becomes one OTel log record with:

| OTel field | Source |
|---|---|
| `Timestamp` | `AuditEntry.Timestamp` |
| `SeverityText` / `SeverityNumber` | `AuditEntry.Severity` mapped to OTel SeverityNumber |
| `Body` | `AuditEntry.Summary` (formatted message) |
| Attribute `ai.sentinel.detector.id` | `AuditEntry.DetectorId` |
| Attribute `ai.sentinel.severity` | enum name (`"High"`, `"Critical"`, etc.) |
| Attribute `ai.sentinel.audit.id` | `AuditEntry.Id` |
| Attribute `ai.sentinel.audit.hash` | `AuditEntry.Hash` |
| Attribute `ai.sentinel.audit.previous_hash` | `AuditEntry.PreviousHash` |
| Resource attributes | Whatever your OTel SDK config provides — `service.name`, `service.version`, etc. |

The `ai.sentinel.*` attribute namespace is the canonical way to filter audit records from your other application logs in downstream observability tools.

## Severity mapping

| AI.Sentinel | OTel SeverityNumber | OTel SeverityText |
|---|---|---|
| `Critical` | 21 | `"FATAL"` |
| `High` | 17 | `"ERROR"` |
| `Medium` | 13 | `"WARN"` |
| `Low` | 9 | `"INFO"` |
| `None` | 9 | `"INFO"` (Clean entries — typically filtered out at the SIEM) |

The mapping uses standard OTel severity ranges so log aggregators that respect the spec render colors / dashboard widgets correctly.

## Batching

`OpenTelemetryAuditForwarder` is **not** auto-wrapped in `BufferingAuditForwarder`. The OTel SDK does its own `BatchLogRecordExportProcessor` batching upstream — adding another layer would be redundant.

Default OTel batch parameters apply:

- `MaxQueueSize`: 2048 records
- `ScheduledDelayMilliseconds`: 5000
- `MaxExportBatchSize`: 512
- `ExportTimeoutMilliseconds`: 30000

Tune via the OTel `BatchExportProcessorOptions` if your traffic profile demands it.

## Backpressure

When the OTel SDK's queue fills (sustained collector downtime + high traffic):

- New records are dropped at the SDK layer (per OTel spec)
- The SDK exposes drop counters via its own metrics — they show up alongside your existing OTel telemetry
- AI.Sentinel's `audit.forward.dropped` counter is **not** incremented for OTel — drops happen at the SDK layer below the forwarder

Monitor OTel SDK drop metrics if you care about delivery; AI.Sentinel can't observe drops below the SDK boundary.

## Where it ships to

OTel is a routing protocol, not a destination. Whatever your OTel collector / SDK is configured to talk to is where AI.Sentinel data lands. Common backends:

| Backend | Setup |
|---|---|
| **Splunk** | Splunk OTel Collector + HEC sink |
| **Elastic** | Elastic Common Schema integration via OTel SDK |
| **Datadog** | Datadog Agent with OTLP receiver |
| **Loki / Grafana Cloud** | Promtail or OTel Collector to Loki |
| **Honeycomb / Lightstep / Tempo / Jaeger** | Standard OTLP backend support |
| **AWS CloudWatch** | OTel Collector with CloudWatch Logs exporter |
| **GCP Cloud Logging** | OTel Collector with GCP exporter |

Your existing OTel pipeline picks AI.Sentinel up "for free" — no per-vendor integration code to write or maintain.

## Filtering and routing

Use OTel's standard log processors / exporters to filter by AI.Sentinel attributes:

```csharp
// Only export High+ severity to your high-cost SIEM, log everything to cheap storage
services.AddOpenTelemetry().WithLogging(b => b
    .AddProcessor(new SeverityFilteringProcessor(min: SeverityNumber.Error))
    .AddOtlpExporter(/* expensive SIEM */));
```

Or filter at the OTel Collector level (not in the AI.Sentinel SDK) — the Collector's [filterprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/filterprocessor) supports OTTL expressions:

```yaml
# otel-collector.yaml
processors:
  filter/sentinel:
    logs:
      include:
        match_type: regexp
        record_attributes:
          - key: ai.sentinel.detector.id
            value: "^SEC-.*"
service:
  pipelines:
    logs/security:
      receivers: [otlp]
      processors: [filter/sentinel, batch]
      exporters: [otlphttp/sentinel]
    logs/all:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/loki]
```

This routes only security-detector audit entries to your security SIEM, while everything else goes to general log storage — handy when SIEM ingestion costs more than warm storage.

## When to use this forwarder

Best fit when:

- You already run an OTel pipeline for application logs / traces / metrics
- You want AI.Sentinel audit on the same observability stack as the rest of your telemetry
- You're vendor-neutral or multi-cloud and don't want a hard dependency on one SIEM SDK
- You want correlation between AI.Sentinel events and trace IDs already flowing through OTel

Less ideal when:

- You don't run an OTel collector and don't want to set one up
- You need direct push to a single SIEM with no intermediary — `AzureSentinelAuditForwarder` (or future direct-Splunk forwarder) is more direct

## Combined with the SQLite store

Recommended production pattern: durable local store + OTel for central observability.

```csharp
services.AddAISentinel(opts => /* ... */);
services.AddSentinelSqliteStore(opts => opts.DatabasePath = "/var/lib/ai-sentinel/audit.db");
services.AddSentinelOpenTelemetryForwarder();
services.AddOpenTelemetry().WithLogging(b => b.AddOtlpExporter());
```

SQLite gives you forensic-grade local audit (hash chain, query API). OTel gives you near-real-time central visibility. Both run independently — neither blocks the other.

## Live integration test

A Docker-Compose-driven integration test that spins up a real OTel Collector + stub backend and verifies round-trip is on the [backlog](https://github.com/ZeroAlloc-Net/AI.Sentinel/blob/main/docs/BACKLOG.md). Today, e2e validation requires manual setup of an OTel Collector pointed at any OTLP receiver.

## Next: [Integrations → Claude Code](../integrations/claude-code) — wire AI.Sentinel into Claude Code's hooks
