# Fluent Per-Detector Config Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Or use superpowers:subagent-driven-development to dispatch a fresh subagent per task with two-stage review.

**Goal:** Add `opts.Configure<T>(c => ...)` to `SentinelOptions` so operators can disable individual detectors or clamp their severity output (Floor/Cap) without forking detector code.

**Architecture:** Pipeline-level concern, not detector-level — detectors stay unaware. `SentinelOptions` accumulates a `Dictionary<Type, DetectorConfiguration>`. `DetectionPipeline` filters disabled detectors at construction time (zero CPU on disabled) and applies Floor/Cap to firing results post-invocation via `DetectionResult with { Severity = clamped }`.

**Tech Stack:** .NET 8/9, xUnit, existing `IDetector` / `DetectionPipeline` infrastructure. No new packages.

**Reference:** [Design doc](2026-04-28-fluent-detector-config-design.md). The DetectorTestBuilder SDK v1.1 plan ([2026-04-28-detector-test-builder.md](2026-04-28-detector-test-builder.md)) is the most recent precedent for plan structure, commit-per-task discipline, and analyzer compliance.

---

## Convention reminders

The codebase runs `TreatWarningsAsErrors=true` with these analyzers that bite easily:

- **MA0002**: explicit `StringComparer.Ordinal` / `StringComparison.Ordinal` required on string compares
- **MA0006**: `string.Equals` without `StringComparison`
- **MA0051**: 60-line method cap; extract a private helper if a method approaches that
- **HLQ001 / HLQ013**: prefer `foreach` for read-only span iteration; suppress with a tightly-scoped `#pragma warning disable HLQ013` + comment for in-place mutation
- **ZA1104**: `Span<T>` may not cross `await` boundaries
- **CA1031**: don't catch `Exception` without justification
- **RCS1194**: exception types should have the canonical 3 ctors (`()`, `(string)`, `(string, Exception)`) — but `DetectorConfiguration` is not an exception, so this doesn't apply here

The main test project at `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj` already has the standard `<NoWarn>` set.

---

## Task 1: `DetectorConfiguration` type + `SentinelOptions` accumulator + `Configure<T>` extension

**Files:**
- Create: `src/AI.Sentinel/Detection/DetectorConfiguration.cs`
- Modify: `src/AI.Sentinel/SentinelOptions.cs` — add accumulator parallel to `_detectorRegistrations`
- Create: `src/AI.Sentinel/SentinelOptionsConfigureExtensions.cs`
- Create: `tests/AI.Sentinel.Tests/Detection/SentinelOptionsConfigureExtensionsTests.cs`

This task ships the registration-side surface only — no pipeline integration. Validates the lambda runs against a shared mutable config object, that `Floor > Cap` throws, and that the accumulator stores per-type configs.

### Step 1: Create `DetectorConfiguration`

Create `src/AI.Sentinel/Detection/DetectorConfiguration.cs`:

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

### Step 2: Add accumulator to `SentinelOptions`

Modify `src/AI.Sentinel/SentinelOptions.cs`. After the existing `_detectorRegistrations` field (line 14) and its accessor methods (lines 25-32), add:

```csharp
private readonly Dictionary<Type, DetectorConfiguration> _detectorConfigurations = new();

/// <summary>Internal access for the pipeline to read per-detector configurations.</summary>
internal IReadOnlyDictionary<Type, DetectorConfiguration> GetDetectorConfigurations() => _detectorConfigurations;

/// <summary>Internal hook for the <c>Configure&lt;T&gt;</c> extension. Returns the existing
/// configuration for <paramref name="detectorType"/> or creates a fresh one with defaults.</summary>
internal DetectorConfiguration GetOrCreateDetectorConfiguration(Type detectorType)
{
    if (!_detectorConfigurations.TryGetValue(detectorType, out var cfg))
    {
        cfg = new DetectorConfiguration();
        _detectorConfigurations[detectorType] = cfg;
    }
    return cfg;
}
```

### Step 3: Create the extension

Create `src/AI.Sentinel/SentinelOptionsConfigureExtensions.cs`:

```csharp
using AI.Sentinel.Detection;

namespace AI.Sentinel;

public static class SentinelOptionsConfigureExtensions
{
    /// <summary>Tune or disable a registered detector. Multiple calls for the same <typeparamref name="T"/>
    /// merge by mutation — each call's lambda runs against the same <see cref="DetectorConfiguration"/>
    /// instance, so independent properties accumulate and same-property writes are last-wins.
    /// <para>
    /// Validation: <see cref="DetectorConfiguration.SeverityFloor"/> must be less than or equal to
    /// <see cref="DetectorConfiguration.SeverityCap"/> when both are set; violations throw
    /// <see cref="ArgumentException"/> at the call site.
    /// </para>
    /// <para>
    /// Configuring a detector type that was never registered is a silent no-op — the type-keyed
    /// lookup simply doesn't fire at runtime.
    /// </para>
    /// </summary>
    public static SentinelOptions Configure<T>(this SentinelOptions opts, Action<DetectorConfiguration> configure)
        where T : IDetector
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(configure);

        var cfg = opts.GetOrCreateDetectorConfiguration(typeof(T));
        configure(cfg);

        if (cfg.SeverityFloor is { } floor && cfg.SeverityCap is { } cap && floor > cap)
        {
            throw new ArgumentException(
                $"DetectorConfiguration for '{typeof(T).Name}' has SeverityFloor ({floor}) > SeverityCap ({cap}). Floor must be <= Cap.",
                nameof(configure));
        }

        return opts;
    }
}
```

### Step 4: Create the test fixture

Create `tests/AI.Sentinel.Tests/Detection/SentinelOptionsConfigureExtensionsTests.cs`:

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class SentinelOptionsConfigureExtensionsTests
{
    private sealed class FakeDetector : IDetector
    {
        private static readonly DetectorId _id = new("FAKE-01");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(_id));
    }

    private sealed class OtherFakeDetector : IDetector
    {
        private static readonly DetectorId _id = new("FAKE-02");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(_id));
    }
}
```

### Step 5: Write the failing tests

Add inside the class:

```csharp
[Fact]
public void Configure_DefaultConfiguration_HasExpectedDefaults()
{
    var opts = new SentinelOptions();
    opts.Configure<FakeDetector>(_ => { });

    var cfg = opts.GetDetectorConfigurations()[typeof(FakeDetector)];
    Assert.True(cfg.Enabled);
    Assert.Null(cfg.SeverityFloor);
    Assert.Null(cfg.SeverityCap);
}

[Fact]
public void Configure_StoresConfigurationKeyedByType()
{
    var opts = new SentinelOptions();
    opts.Configure<FakeDetector>(c => c.Enabled = false);
    opts.Configure<OtherFakeDetector>(c => c.SeverityFloor = Severity.High);

    var configs = opts.GetDetectorConfigurations();
    Assert.False(configs[typeof(FakeDetector)].Enabled);
    Assert.Equal(Severity.High, configs[typeof(OtherFakeDetector)].SeverityFloor);
}

[Fact]
public void Configure_MultipleCalls_MergeByMutation()
{
    var opts = new SentinelOptions();
    opts.Configure<FakeDetector>(c => c.SeverityFloor = Severity.High);
    opts.Configure<FakeDetector>(c => c.SeverityCap = Severity.Critical);

    var cfg = opts.GetDetectorConfigurations()[typeof(FakeDetector)];
    Assert.Equal(Severity.High, cfg.SeverityFloor);
    Assert.Equal(Severity.Critical, cfg.SeverityCap);
}

[Fact]
public void Configure_SameProperty_LastWins()
{
    var opts = new SentinelOptions();
    opts.Configure<FakeDetector>(c => c.SeverityFloor = Severity.High);
    opts.Configure<FakeDetector>(c => c.SeverityFloor = Severity.Critical);

    var cfg = opts.GetDetectorConfigurations()[typeof(FakeDetector)];
    Assert.Equal(Severity.Critical, cfg.SeverityFloor);
}

[Fact]
public void Configure_FloorGreaterThanCap_ThrowsAtRegistration()
{
    var opts = new SentinelOptions();

    var ex = Assert.Throws<ArgumentException>(() =>
        opts.Configure<FakeDetector>(c =>
        {
            c.SeverityFloor = Severity.Critical;
            c.SeverityCap = Severity.Low;
        }));

    Assert.Contains("FakeDetector", ex.Message, StringComparison.Ordinal);
    Assert.Contains("Floor", ex.Message, StringComparison.Ordinal);
    Assert.Contains("Cap", ex.Message, StringComparison.Ordinal);
}

[Fact]
public void Configure_NullConfigureLambda_ThrowsArgumentNullException()
{
    var opts = new SentinelOptions();
    Assert.Throws<ArgumentNullException>(() => opts.Configure<FakeDetector>(null!));
}
```

### Step 6: Run the tests to verify they fail then pass

Run: `dotnet test tests/AI.Sentinel.Tests --nologo -v minimal --filter "FullyQualifiedName~SentinelOptionsConfigureExtensionsTests"`

Expected on first run: build errors (`Configure<T>`, `GetDetectorConfigurations`, `GetOrCreateDetectorConfiguration` don't exist). After Steps 1-3 are in place, all 6 tests pass on net8.0 + net10.0.

### Step 7: Commit

```bash
git add src/AI.Sentinel/Detection/DetectorConfiguration.cs \
        src/AI.Sentinel/SentinelOptions.cs \
        src/AI.Sentinel/SentinelOptionsConfigureExtensions.cs \
        tests/AI.Sentinel.Tests/Detection/SentinelOptionsConfigureExtensionsTests.cs
git commit -m "feat(detection): DetectorConfiguration + opts.Configure<T>() — registration-side surface"
```

Self-review: (1) `DetectorConfiguration` is `sealed` with three settable properties + `Enabled = true` default, (2) accumulator stores per-type configs and exposes `GetOrCreateDetectorConfiguration` to the extension, (3) `Configure<T>` validates Floor ≤ Cap after the lambda runs, (4) lambda null-guard fires before the validation check.

---

## Task 2: Pipeline integration — `Enabled = false` skip-at-construction

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs` — accept configurations + filter
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs` — pass `opts.GetDetectorConfigurations()` to the pipeline
- Create: `tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs`

The pipeline filters disabled detectors at construction time so `RunAsync` never even sees them. Detectors are registered as singletons and the pipeline is a singleton, so config is fixed at startup — no runtime-toggle requirement.

### Step 1: Add a counting-stub detector to the test fixture

Create `tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs`:

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class PipelineDetectorConfigTests
{
    private sealed class CountingDetector(Severity severity, string id = "COUNT-01") : IDetector
    {
        public int InvocationCount { get; private set; }
        private readonly DetectorId _id = new(id);
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            InvocationCount++;
            return ValueTask.FromResult(severity == Severity.None
                ? DetectionResult.Clean(_id)
                : DetectionResult.WithSeverity(_id, severity, "stub"));
        }
    }

    private static SentinelContext NewContext()
    {
        return new SentinelContext(
            new AgentId("user"),
            new AgentId("assistant"),
            SessionId.New(),
            messages: [],
            history: []);
    }
}
```

### Step 2: Write the failing test — disabled detector is not invoked

Add inside the class:

```csharp
[Fact]
public async Task Configure_Enabled_False_DetectorIsNotInvoked()
{
    var detector = new CountingDetector(Severity.High, "DIS-01");
    var opts = new SentinelOptions();
    opts.Configure<CountingDetector>(c => c.Enabled = false);

    var pipeline = new DetectionPipeline(
        new IDetector[] { detector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    Assert.Equal(0, detector.InvocationCount);
    Assert.Empty(result.Findings);
}
```

### Step 3: Write the failing test — enabled detector still runs

```csharp
[Fact]
public async Task Configure_Enabled_True_DetectorRuns()
{
    var detector = new CountingDetector(Severity.High);
    var opts = new SentinelOptions();
    opts.Configure<CountingDetector>(c => c.Enabled = true);  // explicit, default

    var pipeline = new DetectionPipeline(
        new IDetector[] { detector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    Assert.Equal(1, detector.InvocationCount);
    Assert.Single(result.Findings);
    Assert.Equal(Severity.High, result.Findings[0].Severity);
}
```

### Step 4: Run tests to verify they fail

Run: `dotnet test tests/AI.Sentinel.Tests --nologo -v minimal --filter "FullyQualifiedName~PipelineDetectorConfigTests"`

Expected: build errors — `DetectionPipeline` doesn't accept a configurations dictionary yet.

### Step 5: Update `DetectionPipeline` constructor

Modify `src/AI.Sentinel/Detection/DetectionPipeline.cs`. Change the constructor signature to accept configurations and filter disabled detectors. Replace the existing constructor (lines 10-22) with:

```csharp
private readonly IDetector[] _detectors;
private readonly DetectorConfiguration?[] _configurations;
private readonly IChatClient? _escalationClient;
private readonly ILogger<DetectionPipeline>? _logger;

public DetectionPipeline(
    IEnumerable<IDetector> detectors,
    IReadOnlyDictionary<Type, DetectorConfiguration>? configurations,
    IChatClient? escalationClient,
    ILogger<DetectionPipeline>? logger = null)
{
    var enabled = new List<IDetector>();
    var enabledConfigs = new List<DetectorConfiguration?>();
    foreach (var d in detectors)
    {
        DetectorConfiguration? cfg = null;
        if (configurations is not null)
        {
            configurations.TryGetValue(d.GetType(), out cfg);
        }

        if (cfg is not null && !cfg.Enabled)
        {
            continue;  // skip disabled detector entirely — zero CPU on the hot path
        }

        enabled.Add(d);
        enabledConfigs.Add(cfg);
    }

    _detectors = enabled.ToArray();
    _configurations = enabledConfigs.ToArray();
    _escalationClient = escalationClient;
    _logger = logger;
}
```

Add the `using` for `AI.Sentinel.Detection`'s sibling type — `DetectorConfiguration` is in the same namespace, so no extra `using`.

### Step 6: Update the existing single-arg constructor callers (none expected)

Search for callers of `new DetectionPipeline(`:

```bash
grep -rn "new DetectionPipeline(" src/ tests/
```

If `ServiceCollectionExtensions.cs:43` is the only caller, update it next. If there are test-side callers, they'll need to pass `configurations: null` explicitly (or `opts.GetDetectorConfigurations()` if the test owns options).

### Step 7: Update `ServiceCollectionExtensions`

Modify `src/AI.Sentinel/ServiceCollectionExtensions.cs:43`. Replace:

```csharp
new DetectionPipeline(sp.GetServices<IDetector>(), opts.EscalationClient, sp.GetService<ILogger<DetectionPipeline>>())));
```

with:

```csharp
new DetectionPipeline(
    sp.GetServices<IDetector>(),
    opts.GetDetectorConfigurations(),
    opts.EscalationClient,
    sp.GetService<ILogger<DetectionPipeline>>())));
```

### Step 8: Run tests to verify they pass

Run: `dotnet test tests/AI.Sentinel.Tests --nologo -v minimal`

Expected: all 487 v1.0 tests still pass + 6 from Task 1 + 2 from Task 2 = 495 total. If anything in `DetectionPipelineTests` or `PipelineForwarderIntegrationTests` breaks because of the new constructor signature, those test sites need a `configurations: null` argument inserted.

### Step 9: Commit

```bash
git add src/AI.Sentinel/Detection/DetectionPipeline.cs \
        src/AI.Sentinel/ServiceCollectionExtensions.cs \
        tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs
git commit -m "feat(detection): pipeline skips disabled detectors at construction (Configure<T>(c => c.Enabled = false))"
```

Self-review: (1) disabled detectors filtered at ctor, never enter the `_detectors` array, (2) `_configurations` parallel array indexed by detector position avoids per-request dictionary lookups for Task 3, (3) callers pass either the real config dictionary or `null` (no behavior change), (4) all v1.0 tests still pass.

---

## Task 3: Pipeline integration — `SeverityFloor` / `SeverityCap` clamping

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs` — apply Floor/Cap to firing results post-invocation
- Modify: `tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs` — add 6 clamp tests

### Step 1: Write the failing tests — Floor on firing result

Add to `PipelineDetectorConfigTests.cs`:

```csharp
[Fact]
public async Task Configure_SeverityFloor_ElevatesFiringResult()
{
    var detector = new CountingDetector(Severity.Low, "FLR-01");
    var opts = new SentinelOptions();
    opts.Configure<CountingDetector>(c => c.SeverityFloor = Severity.High);

    var pipeline = new DetectionPipeline(
        new IDetector[] { detector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    Assert.Single(result.Findings);
    Assert.Equal(Severity.High, result.Findings[0].Severity);
    Assert.Equal("FLR-01", result.Findings[0].DetectorId.Value, StringComparer.Ordinal);
    Assert.Equal("stub", result.Findings[0].Reason, StringComparer.Ordinal);  // reason preserved
}

[Fact]
public async Task Configure_SeverityFloor_LeavesCleanUntouched()
{
    var detector = new CountingDetector(Severity.None, "CLN-01");
    var opts = new SentinelOptions();
    opts.Configure<CountingDetector>(c => c.SeverityFloor = Severity.Critical);

    var pipeline = new DetectionPipeline(
        new IDetector[] { detector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    Assert.Empty(result.Findings);  // Clean stays Clean — no fabricated finding
}
```

### Step 2: Write the failing tests — Cap on firing result

```csharp
[Fact]
public async Task Configure_SeverityCap_DowngradesFiringResult()
{
    var detector = new CountingDetector(Severity.Critical, "CAP-01");
    var opts = new SentinelOptions();
    opts.Configure<CountingDetector>(c => c.SeverityCap = Severity.Low);

    var pipeline = new DetectionPipeline(
        new IDetector[] { detector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    Assert.Single(result.Findings);
    Assert.Equal(Severity.Low, result.Findings[0].Severity);
}

[Fact]
public async Task Configure_SeverityCap_LeavesCleanUntouched()
{
    var detector = new CountingDetector(Severity.None);
    var opts = new SentinelOptions();
    opts.Configure<CountingDetector>(c => c.SeverityCap = Severity.High);

    var pipeline = new DetectionPipeline(
        new IDetector[] { detector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    Assert.Empty(result.Findings);
}
```

### Step 3: Write the failing tests — Floor + Cap composition + unknown type

```csharp
[Fact]
public async Task Configure_FloorAndCap_BothApply()
{
    // Detector fires Low; Floor=Medium → elevated to Medium. Cap=High doesn't kick in.
    var lowDetector = new CountingDetector(Severity.Low, "BOTH-LOW");
    // Detector fires Critical; Cap=High → downgraded to High. Floor=Medium doesn't kick in.
    var critDetector = new CountingDetector(Severity.Critical, "BOTH-CRIT");

    var opts = new SentinelOptions();
    opts.Configure<CountingDetector>(c =>
    {
        c.SeverityFloor = Severity.Medium;
        c.SeverityCap = Severity.High;
    });

    var pipeline = new DetectionPipeline(
        new IDetector[] { lowDetector, critDetector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    var bothLow = result.Findings.First(f => f.DetectorId.Value == "BOTH-LOW");
    var bothCrit = result.Findings.First(f => f.DetectorId.Value == "BOTH-CRIT");
    Assert.Equal(Severity.Medium, bothLow.Severity);  // Low elevated by Floor
    Assert.Equal(Severity.High, bothCrit.Severity);   // Critical downgraded by Cap
}

[Fact]
public async Task Configure_UnknownDetectorType_SilentNoOp()
{
    // Configure references a type that's never registered as a detector.
    // The pipeline should ignore it — no throw, no effect on actually-registered detectors.
    var detector = new CountingDetector(Severity.High, "REAL-01");
    var opts = new SentinelOptions();
    opts.Configure<UnregisteredDetectorType>(c => c.SeverityCap = Severity.Low);

    var pipeline = new DetectionPipeline(
        new IDetector[] { detector },
        opts.GetDetectorConfigurations(),
        escalationClient: null,
        logger: null);

    var result = await pipeline.RunAsync(NewContext(), CancellationToken.None);

    Assert.Single(result.Findings);
    Assert.Equal(Severity.High, result.Findings[0].Severity);  // unchanged
}

private sealed class UnregisteredDetectorType : IDetector
{
    private static readonly DetectorId _id = new("UNREG-01");
    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;
    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        => ValueTask.FromResult(DetectionResult.Clean(_id));
}
```

### Step 4: Run tests to verify they fail

Run: `dotnet test tests/AI.Sentinel.Tests --nologo -v minimal --filter "FullyQualifiedName~PipelineDetectorConfigTests"`

Expected: 6 new tests fail because Floor/Cap aren't applied yet (the disabled-detector and Enabled=true tests from Task 2 still pass).

### Step 5: Apply Floor/Cap in `DetectionPipeline.RunAsync`

Modify `src/AI.Sentinel/Detection/DetectionPipeline.cs`. After the detector results are gathered (after the existing `// Slow path` block, around line 60) and before the LLM-escalation block (around line 67), insert the clamp pass:

```csharp
// Apply per-detector severity clamp (Floor/Cap) to firing results.
// Clean results pass through untouched per the design contract.
for (int i = 0; i < results.Length; i++)
{
    var cfg = _configurations[i];
    if (cfg is null || results[i].IsClean) continue;

    var clamped = results[i].Severity;
    if (cfg.SeverityFloor is { } floor && clamped < floor) clamped = floor;
    if (cfg.SeverityCap is { } cap && clamped > cap) clamped = cap;

    if (clamped != results[i].Severity)
    {
        results[i] = results[i] with { Severity = clamped };
    }
}
```

`DetectionResult` is a `sealed record` so the `with`-expression rewrites Severity while preserving `DetectorId` and `Reason`.

### Step 6: Run tests to verify they pass

Run: `dotnet test tests/AI.Sentinel.Tests --nologo -v minimal`

Expected: 14 tests in `PipelineDetectorConfigTests` pass (2 from Task 2 + 6 from Task 3 = 8 actually; the rest are in `SentinelOptionsConfigureExtensionsTests`). Total run: 487 v1.0 + 6 + 8 = 501.

### Step 7: Commit

```bash
git add src/AI.Sentinel/Detection/DetectionPipeline.cs \
        tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs
git commit -m "feat(detection): pipeline applies SeverityFloor/SeverityCap to firing results (Configure<T>)"
```

Self-review: (1) Clean results bypass the clamp via `IsClean` check, (2) `with`-expression preserves DetectorId + Reason, (3) Floor and Cap can both be set and compose correctly, (4) unregistered types in `Configure<T>` are silent no-ops because their key is never in `_configurations[i]`.

---

## Task 4: README + BACKLOG cleanup + e2e smoke

**Files:**
- Modify: `README.md` — add `Configure<T>` section
- Modify: `docs/BACKLOG.md` — remove "Fluent per-detector config" row
- Modify: `tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs` — add e2e smoke through `SentinelChatClient`

### Step 1: Add an e2e smoke test

The unit tests above exercise `DetectionPipeline` directly. The smoke test wires the full `services.AddAISentinel(...)` setup with a real `SentinelChatClient` to confirm that disabled detectors don't reach audit and that Floor-elevated detectors land at the elevated severity in the audit chain.

Add to `PipelineDetectorConfigTests.cs`. Use the existing `services.AddAISentinel(...)` test pattern from `tests/AI.Sentinel.Tests/Pipeline/SentinelChatClientPipelineTests.cs` (or whichever file has the e2e setup) — the implementer should grep for an existing test that constructs `SentinelChatClient` end-to-end and copy its setup. The smoke is one test:

```csharp
[Fact]
public async Task EndToEnd_DisabledDetectorAndFloorElevation_FlowThroughPipelineAndAudit()
{
    // Use a custom AddDetector<T>() to register two stub detectors.
    // - DisabledFiringDetector would fire High but is disabled → no audit entry.
    // - FloorElevatedFiringDetector fires Low; Floor=High → audit records High.

    // [Implementer: locate the existing SentinelChatClient e2e test pattern and mirror it.
    //  The exact wiring depends on the test harness; the assertion shape is:
    //  - audit store contains exactly one entry, for FloorElevatedFiringDetector, at Severity.High
    //  - DisabledFiringDetector contributes nothing]

    // If no e2e harness exists in tests/AI.Sentinel.Tests/Pipeline/,
    // skip this step and rely on the unit tests in Tasks 2-3 — they already
    // cover the contract. Note in the commit message that an e2e smoke is
    // deferred pending a suitable harness.
}
```

If the existing test suite has no clean `SentinelChatClient + AuditStore` e2e pattern that fits Configure<T>, **skip this step** — the 8 unit tests in Tasks 2-3 already cover the contract through `DetectionPipeline` directly, which is the same code path SentinelChatClient invokes. Note the deferral in the commit message.

### Step 2: Update main `README.md`

Find the section in `README.md` that documents `services.AddAISentinel(opts => ...)` configuration — typically a "Configuration" or "Quick start" block. Add (or extend) a subsection covering `Configure<T>`:

```markdown
### Tuning individual detectors

Use `opts.Configure<T>(c => ...)` to disable a detector or clamp its severity output:

\`\`\`csharp
services.AddAISentinel(opts =>
{
    // Disable a detector entirely — zero CPU cost, no audit entries
    opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);

    // Elevate any firing of JailbreakDetector to at least High
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);

    // Cap a noisy detector's output to Low
    opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);
});
\`\`\`

`Floor` and `Cap` apply only to *firing* results — Clean results pass through unchanged
(no fabricated findings). Multiple `Configure<T>` calls for the same detector merge by
mutation, so base configuration and per-environment overrides compose naturally.
```

(Replace `\`\`\`` with real triple-backticks when writing.)

Place it after the existing `AddDetector<T>()` documentation if there is one; before the "Detectors" reference table otherwise.

### Step 3: Update `docs/BACKLOG.md`

Find the row in the Architecture / Integration table:

```markdown
| **Fluent per-detector config** | `opts.Configure<PromptInjectionDetector>(d => d.Severity = Severity.High)` — tune or disable individual detectors without removing them from the pipeline |
```

**Remove** that row entirely. No follow-up items needed — Scope B (per-detector type-specific knobs) accretes per real user request as a separate design exercise; the entry doesn't belong in the backlog yet because no specific knob has been requested.

### Step 4: Run all tests + sanity build

```bash
dotnet test AI.Sentinel.slnx --nologo -v minimal
dotnet build AI.Sentinel.slnx -c Debug --nologo -v minimal
```

Expected:
- All test projects pass on net8.0 + net10.0
- `AI.Sentinel.Tests`: 487 v1.0 + 14 new = 501 (or 502 if the e2e smoke landed)
- 0 warnings, 0 errors

Note pre-existing flake possibilities (`BufferingAuditForwarderTests.SizeThreshold_FlushesBatch`, `PipelineForwarderIntegrationTests.SlowForwarder_DoesNotBlockPipeline` — timing flakes on net8.0). Pass on rerun.

### Step 5: Commit

```bash
git add README.md docs/BACKLOG.md tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs
git commit -m "docs+test(detection): Configure<T>() README + e2e smoke + backlog cleanup"
```

Self-review: (1) README has a worked Configure<T>() example covering all three knobs, (2) BACKLOG removes the now-shipped item with no leftover stragglers, (3) e2e smoke landed (or deferral noted in commit), (4) full solution builds 0/0 and all test projects pass.

---

## Final review checklist

After Task 4, dispatch the `superpowers:code-reviewer` agent for cross-cutting review against:

- The design doc at [docs/plans/2026-04-28-fluent-detector-config-design.md](2026-04-28-fluent-detector-config-design.md)
- This plan
- Existing AI.Sentinel conventions (MA0002/MA0006 ordinal-string, no XML doc noise, public/internal split, `[InternalsVisibleTo]` patterns)
- All decisions from the design (Q1 universal knobs, Q2 Clean stays Clean, Q3 single Configure<T>, Q4 skip-on-disabled, Q5 merge-by-mutation)

Then run `superpowers:finishing-a-development-branch`.

**Total estimated scope:** ~120 LOC implementation, ~250 LOC tests, 4 tasks, 14 unit tests + (optional) 1 e2e smoke, no new NuGet package. Should land in 1-1.5 hours of focused work.
