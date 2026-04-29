---
sidebar_position: 3
title: Dashboard
---

# Dashboard

`AI.Sentinel.AspNetCore` ships an embedded real-time dashboard at any URL prefix you choose:

```csharp
app.UseAISentinel("/ai-sentinel");
```

No JS framework — HTMX + Server-Sent Events drive the live audit feed.

> Full dashboard guide — feature flags, authentication, threat heatmap, severity trend charts — coming soon.
