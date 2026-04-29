---
sidebar_position: 2
title: Dev / staging / prod
---

# Dev / staging / prod cookbook

Use named pipelines per environment so dev allows pass-through while prod quarantines:

```csharp
services.AddAISentinel("dev", opts =>
{
    opts.OnCritical = SentinelAction.Log;       // never block in dev
    opts.OnHigh     = SentinelAction.Log;
});
services.AddAISentinel("staging", opts =>
{
    opts.OnCritical = SentinelAction.Alert;     // alert in staging, don't block
});
services.AddAISentinel("prod", opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.OnHigh     = SentinelAction.Alert;
});

// pick based on environment
var env = builder.Configuration["Environment"];  // "dev" / "staging" / "prod"
services.AddChatClient(b => b.UseAISentinel(env).Use(new OpenAIChatClient(...)));
```

For shared base config, extract a helper:

```csharp
Action<SentinelOptions> baseCfg = opts =>
{
    opts.EmbeddingGenerator = realGen;
    opts.AuditCapacity = 50_000;
};
services.AddAISentinel(baseCfg);
services.AddAISentinel("prod", opts =>
{
    baseCfg(opts);
    opts.OnCritical = SentinelAction.Quarantine;
});
```

> Full env-tier cookbook — config-file driven names, secrets management, blue/green migrations — coming soon.
