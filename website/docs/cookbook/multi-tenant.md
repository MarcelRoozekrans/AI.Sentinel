---
sidebar_position: 1
title: Multi-tenant
---

# Multi-tenant cookbook

For SaaS apps where different tenants need different detector configurations, use [named pipelines](../configuration/named-pipelines):

```csharp
services.AddAISentinel(opts => opts.EmbeddingGenerator = realGen);
services.AddAISentinel("tenant-a", opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.Configure<PiiLeakageDetector>(c => c.SeverityFloor = Severity.Critical);
});
services.AddAISentinel("tenant-b", opts =>
{
    opts.OnCritical = SentinelAction.Log;  // tenant B opted out of strict PII enforcement
    opts.Configure<PiiLeakageDetector>(c => c.Enabled = false);
});
```

Per-request tenant routing (selecting which named pipeline to use based on the incoming request's tenant ID) is **Phase B** — currently you wire one chat client per named pipeline and route at the host level.

> Full multi-tenant cookbook — chat-client-per-tenant pattern, audit isolation considerations, Phase B preview — coming soon.
