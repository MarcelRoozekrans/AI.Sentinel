---
sidebar_position: 4
title: Azure Sentinel
---

# Azure Sentinel forwarder

`AI.Sentinel.AzureSentinel` ships `AzureSentinelAuditForwarder`, which ships audit entries to Microsoft Sentinel via the Azure Monitor **Logs Ingestion API**. Authenticates via `DefaultAzureCredential` (managed identity in production).

```csharp
services.AddSentinelAzureSentinelForwarder(new AzureSentinelAuditForwarderOptions
{
    DataCollectionEndpoint = new Uri("https://...ingest.monitor.azure.com"),
    DataCollectionRuleId = "dcr-...",
    StreamName = "Custom-AISentinel_CL",
});
```

Wrapped in `BufferingAuditForwarder` by default (batch=100, interval=5s).

> Full Azure Sentinel guide — DCR setup, managed identity configuration, KQL query templates — coming soon.
