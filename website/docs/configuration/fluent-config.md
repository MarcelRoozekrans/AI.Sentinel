---
sidebar_position: 2
title: Fluent per-detector config
---

# Fluent per-detector config

`opts.Configure<T>(c => ...)` disables a detector or clamps its severity output:

```csharp
services.AddAISentinel(opts =>
{
    // Disable a detector entirely — zero CPU cost, no audit entries
    opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);

    // Elevate any firing of JailbreakDetector to at least High
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);

    // Cap a noisy detector's output to Low
    opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);
});
```

`Floor` and `Cap` apply only to *firing* results — Clean results pass through unchanged. Multiple `Configure<T>` calls for the same detector merge by mutation.

> Full configuration guide — `DetectorConfiguration` API, validation rules, integration with named pipelines — coming soon.
