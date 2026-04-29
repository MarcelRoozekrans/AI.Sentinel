---
sidebar_position: 1
title: Overview
---

# Audit forwarders overview

`IAuditForwarder` ships every `AuditEntry` to an external sink. Multiple forwarders can be registered; each runs independently. Built-in implementations:

| Forwarder | Package | Use case |
|---|---|---|
| `NdjsonFileAuditForwarder` | `AI.Sentinel` (core) | Local file, ship via Filebeat / Vector / Fluent Bit |
| `SqliteAuditStore` (also `IAuditStore`) | `AI.Sentinel.Sqlite` | Persistent local audit with hash-chain integrity |
| `AzureSentinelAuditForwarder` | `AI.Sentinel.AzureSentinel` | Azure Monitor Logs Ingestion API |
| `OpenTelemetryAuditForwarder` | `AI.Sentinel.OpenTelemetry` | OTel collector (vendor-neutral) |

Wrap any forwarder with `BufferingAuditForwarder` for backpressure control:

```csharp
services.AddSentinelAzureSentinelForwarder(opts => /* ... */);
// internally wraps the forwarder in BufferingAuditForwarder(maxBatch: 100, maxInterval: 5s)
```

> Full forwarder guide — coming soon.
