---
sidebar_position: 2
title: Fluent per-detector config
---

# Fluent per-detector config

`opts.Configure<T>(c => ...)` enables or disables a detector, clamps its severity output (Floor / Cap), or sets a semantic detector's similarity thresholds, without forking detector code. Pipeline-level concern — detectors stay unaware of configuration.

## The knobs

```csharp
public sealed class DetectorConfiguration
{
    public bool? Enabled { get; set; }          // null: the detector's own default
    public Severity? SeverityFloor { get; set; }
    public Severity? SeverityCap { get; set; }
    public SentinelAction? Action { get; set; }
    public float? HighThreshold { get; set; }   // semantic detectors only
    public float? MediumThreshold { get; set; } // semantic detectors only
}
```

| Knob | Effect |
|---|---|
| `Enabled = false` | Pipeline skips invoking this detector entirely. Zero CPU cost — disabled detectors never enter the `_detectors` array at construction time. |
| `Enabled = true` | Runs an opt-in detector. Left unset (`null`), each detector uses its `IDetector.EnabledByDefault`: on for every detector except the four [Art. 5 compliance detectors](../detectors/compliance), which are off until enabled. |
| `HighThreshold` / `MediumThreshold` | Similarity at or above which a semantic detector reports High / Medium, in place of its built-in value. Must be in (0, 1], with Medium not above High. Setting either on a detector that is not a `SemanticDetectorBase` is an `ArgumentException` at `AddAISentinel`. |
| `SeverityFloor = High` | Clamp upward — any **firing** result emitted below `High` is rewritten to `High`. Clean results pass through unchanged (no fabricated findings). |
| `SeverityCap = Low` | Clamp downward — any firing result emitted above `Low` is rewritten to `Low`. Clean results unchanged. |

## Common patterns

### Disable a noisy detector

```csharp
opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);
opts.Configure<RepetitionLoopDetector>(c => c.Enabled = false);
```

### Promote a borderline detector

```csharp
// Anything JailbreakDetector flags should at least page on-call
opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
```

### Cap a noisy detector

```csharp
// PiiLeakage emits Critical for credit cards by default — cap to Medium so it logs but doesn't quarantine
opts.Configure<PiiLeakageDetector>(c => c.SeverityCap = Severity.Medium);
```

### Cap and floor simultaneously

```csharp
// Always emit Medium-or-Low for this detector, never higher, never lower
opts.Configure<MyNoisyDetector>(c =>
{
    c.SeverityFloor = Severity.Low;
    c.SeverityCap = Severity.Medium;
});
```

### Tune a semantic detector's thresholds

Similarity scales differ between embedding models, so a semantic detector's built-in thresholds suit some models better than others. Override them per detector:

```csharp
opts.Configure<JailbreakDetector>(c =>
{
    c.HighThreshold = 0.80f;
    c.MediumThreshold = 0.72f;
});
```

When a pipeline is built, an override is checked against the other, built-in threshold: lowering only `HighThreshold` below the detector's built-in Medium is an `InvalidOperationException`, so lower both. Each named pipeline applies its own thresholds even though the detector instance is shared: the pipeline passes them with each call.

## How clamping works

The `DetectionPipeline` runs every detector, then applies the clamp pass between dispatch and LLM escalation:

```
[detect] → [clamp Floor/Cap] → [escalate ILlmEscalatingDetector hits] → [aggregate]
```

The clamp uses the C# record `with`-expression so `DetectorId` and `Reason` are preserved verbatim:

```csharp
result = result with { Severity = clamped };
```

**Clean results bypass the clamp.** A `Severity.None` from a detector that didn't fire stays `None` — `Floor = High` does not fabricate a finding.

## Multiple `Configure<T>` calls merge by mutation

If you call `Configure<T>` more than once for the same detector type, both calls apply against the **same** configuration instance. Later calls overwrite earlier ones on a per-property basis:

```csharp
opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.Medium);
opts.Configure<JailbreakDetector>(c =>
{
    // SeverityFloor is still Medium from the previous call
    c.SeverityCap = Severity.Critical;  // adds a cap
});
// Net effect: Floor=Medium, Cap=Critical, Enabled=null (the detector's default)
```

This is by design — lets you split configuration across helper methods, environment overlays, etc.

## Where it lives

`Configure<T>` lives on `SentinelOptions` (extension method). It works inside any `AddAISentinel` overload — default or named:

```csharp
services.AddAISentinel(opts =>
{
    // default pipeline tuning
    opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);
});

services.AddAISentinel("strict", opts =>
{
    // strict pipeline tuning — independent of default
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
});
```

In a [named-pipeline setup](./named-pipelines), each pipeline has its own `DetectorConfiguration` dictionary — `Configure<T>` on `"strict"` doesn't leak into `"lenient"`.

## What `Configure<T>` does NOT do

- **It doesn't add detectors** — the detector type `T` must already be registered (built-in via DI source-gen, or via `opts.AddDetector<T>()`)
- **It doesn't expose detector-internal knobs** — `Configure<PiiLeakageDetector>` can't set `IncludePhoneNumbers = false`. That's a per-detector-config feature still on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). The universal knobs (Enabled/Floor/Cap/Action, and the thresholds for semantic detectors) cover the 90% case for any detector.
- **It doesn't fabricate findings** — Floor only clamps *firing* results. If a detector emits Clean, no Floor will turn it into a finding.

## Silent no-op for unmatched types

`Configure<T>` keys on `T` (the runtime type). If you call `Configure<NeverRegistered>` for a type that isn't registered as a detector, the call **silently no-ops** — no exception, no warning. This avoids breaking ordering coupling between `AddDetector` and `Configure`.

A startup warning for unmatched type configurations is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). Today, double-check your detector type names if a `Configure<T>` call seems to have no effect.

A common gotcha: configuring an abstract base class:

```csharp
// ❌ Doesn't work — pipeline keys on detector.GetType(), which is the concrete subclass
opts.Configure<SemanticDetectorBase>(c => c.Enabled = false);

// ✓ Configure each concrete type
opts.Configure<JailbreakDetector>(c => c.Enabled = false);
opts.Configure<MyJailbreakDetector>(c => c.Enabled = false);
```

## Detector-author perspective

Detector authors don't need to do anything special to support `Configure<T>` — the framework applies clamps post-invocation. Your detector should emit an honest severity given what fired; the operator decides what to *do* about it via Configure.

If your detector wants to expose detector-specific knobs (timeouts, threshold overrides), today the pattern is to subclass and override the relevant property:

```csharp
public sealed class StricterJailbreakDetector(SentinelOptions opts) : JailbreakDetector(opts)
{
    protected override float HighThreshold => 0.85f;  // tighter than default 0.90
    protected override float LowThreshold  => 0.65f;  // looser low bucket
}

services.AddAISentinel(opts =>
{
    opts.AddDetector<StricterJailbreakDetector>();
});
```

A first-class detector-specific config API (`opts.Configure<PiiLeakageDetector>(d => d.IncludePhoneNumbers = false)`) is on the backlog under "Scope B" of the fluent-detector-config feature.

## Next: [Embedding cache](./embedding-cache) — speed up semantic detection
