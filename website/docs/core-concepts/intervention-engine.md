---
sidebar_position: 3
title: Intervention engine
---

# Intervention engine

`InterventionEngine` decides what to do when a detection fires. Configure per-severity actions via `SentinelOptions`:

```csharp
opts.OnCritical = SentinelAction.Quarantine;
opts.OnHigh     = SentinelAction.Alert;
opts.OnMedium   = SentinelAction.Log;
opts.OnLow      = SentinelAction.Log;
```

| Action | Effect |
|---|---|
| `Quarantine` | Throws `SentinelException`; caller must catch |
| `Alert` | Publishes a Mediator notification |
| `Log` | Writes to logger only |
| `PassThrough` | No action (audit still records the detection) |

> Full intervention engine guide — Mediator integration, custom alert sinks, alert deduplication, exception handling patterns — coming soon.
