---
sidebar_position: 5
title: OpenTelemetry
---

# OpenTelemetry forwarder

`AI.Sentinel.OpenTelemetry` ships `OpenTelemetryAuditForwarder` — vendor-neutral. Audit entries are emitted as OTel log records routed through an OTel collector to any backend (Splunk, Elastic, Loki, Datadog, etc.).

```csharp
services.AddOpenTelemetry()
    .WithLogging(b => b.AddOtlpExporter())
    .Services
    .AddSentinelOpenTelemetryForwarder();
```

> Full OpenTelemetry guide — collector configuration, structured attribute mapping, severity → log level mapping — coming soon.
