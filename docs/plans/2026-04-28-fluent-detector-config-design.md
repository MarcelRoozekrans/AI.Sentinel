# Fluent per-detector config — design

**Status:** approved 2026-04-28
**Closes backlog item:** "Fluent per-detector config" (Architecture / Integration table)

## Goal

Operators tune or disable individual detectors via `opts.Configure<T>(...)` without
forking the detector or rebuilding the pipeline. Three universal knobs — `Enabled`,
`SeverityFloor`, `SeverityCap` — cover the 90% case for every detector (official and
custom). Per-detector knobs (e.g., `IncludePhoneNumbers` on `PiiLeakageDetector`)
accrete later as a separate scope when real users surface the need.

```csharp
services.AddAISentinel(opts =>
{
    opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
    opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);
});
```

Lives in core `AI.Sentinel`, alongside `opts.AddDetector<T>()` (v1.0). Pure addition —
no breaking changes, no new package, no detector code modified.

## Scope

**In scope (Scope A — universal knobs):**
- New public type `DetectorConfiguration` (sealed; `Enabled`, `SeverityFloor`, `SeverityCap`)
- New extension `opts.Configure<T>(Action<DetectorConfiguration>)` on `SentinelOptions`
- Pipeline integration: skip-if-disabled (pre-invocation), clamp-severity (post-invocation)
- ~12 unit tests + 1 e2e smoke
- README mention + BACKLOG cleanup

**Out of scope (Scope B — deferred):**
- Per-detector type-specific knobs (`PiiLeakageDetectorConfig`, `RepetitionLoopDetectorConfig`)
- Shadow-mode / "would-have-fired" telemetry for disabled detectors
- Severity-dependent behavior (e.g., elevate only Low-fires, leave Medium alone)
- Roslyn analyzer warning when `Configure<T>` references a never-registered type

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Q1 — Knob set | **Universal Enabled / Floor / Cap** (Scope A) | Backlog example `d.Severity = Severity.High` doesn't fit reality — detectors emit multiple severities per detector. Universal clamps + disable cover 90%. Per-detector knobs accrete later. |
| Q2 — Floor on Clean | **Clean stays Clean** | Floor never fabricates findings. Floor is "minimum severity *when* fired", not "minimum severity always". Symmetric: Cap also leaves Clean alone. |
| Q3 — Registration shape | **`Configure<T>(Action<DetectorConfiguration>)` non-generic config** | One method, one config type. Mirrors v1.0 `AddDetector<T>()`. Future Scope B per-detector knobs arrive as a separate overload (`Configure<PiiLeakageDetector>(Action<PiiLeakageDetectorConfig>)`). |
| Q4 — `Enabled = false` semantics | **Skip invocation entirely** | Zero-CPU path. "Shadow mode" telemetry is speculative; ships in Scope B if asked. |
| Q5 — Multiple `Configure<T>` calls | **Merge by mutation** | Framework keeps one config per type; each call's lambda runs against the same instance. Independent properties accumulate; same property last-wins. Supports the realistic base-config + per-environment-override pattern. |

## Public API

```csharp
namespace AI.Sentinel.Detection;

/// <summary>Per-detector configuration applied by the pipeline. Constructed via
/// <see cref="SentinelOptionsConfigureExtensions.Configure{T}"/>.</summary>
public sealed class DetectorConfiguration
{
    /// <summary>When false, the pipeline skips invoking this detector entirely (zero CPU cost).
    /// Disabled detectors contribute nothing to audit, intervention, or telemetry.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Minimum severity for *firing* results. Clean results are unaffected.
    /// A detector returning Severity.Low with Floor = High is rewritten to High.</summary>
    public Severity? SeverityFloor { get; set; }

    /// <summary>Maximum severity for firing results. Clean results are unaffected.
    /// A detector returning Severity.Critical with Cap = Low is rewritten to Low.</summary>
    public Severity? SeverityCap { get; set; }
}
```

```csharp
namespace AI.Sentinel;

public static class SentinelOptionsConfigureExtensions
{
    /// <summary>Tune or disable a registered detector. Multiple calls for the same T merge by
    /// mutation — each call's lambda runs against the same DetectorConfiguration instance.
    /// Validation: Floor must be less than or equal to Cap when both are set; violations throw
    /// ArgumentException at the call site.</summary>
    public static SentinelOptions Configure<T>(this SentinelOptions opts, Action<DetectorConfiguration> configure)
        where T : IDetector;
}
```

`SentinelOptions` gains an internal accumulator parallel to v1.0's `_detectorRegistrations`:

```csharp
private readonly Dictionary<Type, DetectorConfiguration> _detectorConfigurations = new();
internal IReadOnlyDictionary<Type, DetectorConfiguration> GetDetectorConfigurations() => _detectorConfigurations;
internal DetectorConfiguration GetOrCreateDetectorConfiguration(Type detectorType);
```

## Pipeline integration

Two changes in the detector dispatch loop:

1. **Pre-invocation**: lookup `_detectorConfigurations` by `detector.GetType()`. If `Enabled == false`, skip — no `AnalyzeAsync` call, no audit, move to the next detector.

2. **Post-invocation**: if the detector returned a non-clean result, apply Floor/Cap by rewriting `Severity` via the record's `with`-expression:

   ```csharp
   if (!result.IsClean && config is not null)
   {
       var clamped = result.Severity;
       if (config.SeverityFloor is { } floor && clamped < floor) clamped = floor;
       if (config.SeverityCap is { } cap && clamped > cap) clamped = cap;
       if (clamped != result.Severity) result = result with { Severity = clamped };
   }
   ```

   `DetectorId` and `Reason` pass through unchanged.

**Lookup cost:** a single `Dictionary<Type, DetectorConfiguration>.TryGetValue` per detector invocation. Sub-microsecond, zero allocations. Acceptable on the hot path.

**Why pipeline-level not detector-level:** detectors stay unaware of configuration. Works uniformly for official + custom detectors. No detector code is modified to ship Scope A.

## Error handling

- `Configure<T>(null)` → `ArgumentNullException`
- After the lambda runs, validate `Floor <= Cap` when both set; violations throw `ArgumentException` from the `Configure<T>` call site (immediate fail-fast at startup; users get a stack trace pointing at their config code, not a runtime mismatch buried in the pipeline).
- `Configure<NeverRegistered>` → silent no-op. Detectors can be registered indirectly (DI scanning, third-party packages); throwing on "unknown types" creates ordering coupling between `AddDetector` and `Configure`. The type-keyed lookup simply never fires.

## Tests

In `tests/AI.Sentinel.Tests/Detection/SentinelOptionsConfigureExtensionsTests.cs` and `tests/AI.Sentinel.Tests/Pipeline/PipelineDetectorConfigTests.cs`:

1. `Configure_Enabled_False_DetectorIsNotInvoked`
2. `Configure_SeverityFloor_ElevatesFiringResult`
3. `Configure_SeverityFloor_LeavesCleanUntouched`
4. `Configure_SeverityCap_DowngradesFiringResult`
5. `Configure_SeverityCap_LeavesCleanUntouched`
6. `Configure_FloorAndCap_BothApply`
7. `Configure_MultipleCalls_MergeByMutation`
8. `Configure_SameProperty_LastWins`
9. `Configure_FloorGreaterThanCap_ThrowsAtRegistration`
10. `Configure_CustomDetectorRegisteredViaAddDetector_OverridesApply`
11. `Configure_UnknownDetectorType_SilentNoOp`
12. `Configure_DisabledDetector_DoesNotEmitAuditEntry`

Plus an e2e smoke through `SentinelChatClient` with one disabled detector and one
Floor-elevated detector to confirm integration through the full pipeline (intervention engine,
audit chain).

## Documentation

- Main repo `README.md`: brief mention in the configuration section with a worked example
- BACKLOG.md: remove the "Fluent per-detector config" row from the Architecture / Integration table
- No SDK README changes — this is a core feature, not an SDK feature

## Risk / open questions

- **Risk:** users `Configure<T>` a detector type that's *almost* registered but spelled differently (typo, wrong namespace). Silent no-op semantics mean the misconfiguration is invisible until they notice the detector still fires at default severities. Mitigation: clear documentation that `Configure` keys on the runtime detector type, not on a registered alias. Future Scope B work could add an `opts.ValidateConfigurations()` method that warns on unmatched types.
- **No open questions** — knob set, override semantics, registration shape, and error handling all settled in Q1–Q5.

## Estimated scope

~120 LOC implementation + ~250 LOC tests, ~1-1.5 days of focused work. 1 new public type, 1 new extension method, ~12 unit tests + 1 e2e smoke. Pipeline integration touches one file (the detector dispatch loop).
