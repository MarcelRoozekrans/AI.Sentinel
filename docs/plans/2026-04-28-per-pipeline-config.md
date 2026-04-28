# Per-pipeline Configuration (Phase A) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Or use superpowers:subagent-driven-development to dispatch a fresh subagent per task with two-stage review.

**Goal:** Add `services.AddAISentinel("name", opts => ...)` and `.UseAISentinel("name")` overloads so operators register multiple isolated AI.Sentinel pipelines under string names; chat clients select one at construction time.

**Architecture:** Each named pipeline gets isolated `SentinelOptions` / `IDetectionPipeline` / `InterventionEngine` via .NET 8+ keyed services (`AddKeyedSingleton` / `GetRequiredKeyedService`). Audit infrastructure (`IAuditStore`, `IAuditForwarder`, `IAlertSink`) stays unkeyed — shared across all pipelines. Detector pool stays globally registered; per-name detector tuning rides on the just-shipped `Configure<T>(c => ...)`. Default unnamed registration keeps its current shape for full v1.0 backward compatibility.

**Tech Stack:** .NET 8/9, xUnit, Microsoft.Extensions.DependencyInjection (keyed services).

**Reference:** [Design doc](2026-04-28-per-pipeline-config-design.md). The Configure<T> plan ([2026-04-28-fluent-detector-config.md](2026-04-28-fluent-detector-config.md)) is the most recent precedent for plan structure and analyzer-compliance discipline.

---

## Convention reminders

`TreatWarningsAsErrors=true` analyzers that bite easily:

- **MA0002 / MA0006**: explicit `StringComparison.Ordinal` / `StringComparer.Ordinal`
- **MA0051**: 60-line method cap — extract a private helper as needed
- **HLQ001 / HLQ013**: prefer `foreach` for read-only span iteration
- **CA1031**: don't catch `Exception` without justification
- **RCS1194**: exception types should have the canonical 3 ctors (n/a here — no new exception types)

The main test project at `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj` has the standard `<NoWarn>`.

---

## Known limitations of Phase A (scope clarifications)

These are NOT bugs — they're explicit Phase B candidates documented up front so the implementer doesn't try to fix them in Phase A:

1. **User detectors registered via `opts.AddDetector<T>()` go into the GLOBAL detector pool**, regardless of which named pipeline registered them. Per-name detector enable/disable is handled by `Configure<T>(c => c.Enabled = false)` in the just-shipped feature. The `RegisterUserDetectors` helper in `ServiceCollectionExtensions.cs:75` calls `services.AddSingleton(typeof(IDetector), ...)` which is unkeyed.
2. **`IToolCallGuard` stays unkeyed (uses unnamed default's auth bindings).** Per-name authorization policies are a Phase B feature. Document this in the README.
3. **No request-time pipeline selector.** That's Phase B.

---

## Task 1: Refactor `AddAISentinel` to extract a private `RegisterPipeline` helper (zero-behavior change)

This is a confidence-building refactor — no new public surface, no behavior change. The single-arg `AddAISentinel(services, configure)` becomes a thin wrapper over a private `RegisterPipeline(services, name: null, configure)` helper. The helper centralizes all the singleton wiring so the named overload (Task 2) can call the same helper with a non-null name.

**Files:**
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs:14-73` — extract the body into a private helper

### Step 1: Read the current method

The current `AddAISentinel(services, configure)` body (lines 17-72) constructs `opts`, runs `configure(opts)`, then registers 5 singletons (`SentinelOptions`, `IAlertSink`, `IAuditStore`, `InterventionEngine`, `IDetectionPipeline`, `IToolCallGuard`) plus calls `services.AddAISentinelDetectors()` + `RegisterUserDetectors(services, opts)`.

### Step 2: Introduce the private helper

Replace the existing method body with a delegation to a new private static `RegisterPipeline`:

```csharp
public static IServiceCollection AddAISentinel(
    this IServiceCollection services,
    Action<SentinelOptions>? configure = null)
{
    return RegisterPipeline(services, name: null, configure);
}

private static IServiceCollection RegisterPipeline(
    IServiceCollection services,
    string? name,
    Action<SentinelOptions>? configure)
{
    var opts = new SentinelOptions();
    configure?.Invoke(opts);

    if (name is null)
    {
        // Default (unnamed) pipeline — unkeyed singletons, full v1.0 backward compat
        services.AddSingleton(opts);
        services.AddSingleton<IAlertSink>(_ => BuildAlertSink(opts));
        services.AddSingleton<IAuditStore>(BuildAuditStore(opts));
        services.AddSingleton(sp => BuildInterventionEngine(opts, sp));
        services.AddAISentinelDetectors();
        RegisterUserDetectors(services, opts);
        services.AddSingleton<IDetectionPipeline>(sp => BuildDetectionPipeline(opts, sp));
        services.AddSingleton<IToolCallGuard>(sp => BuildToolCallGuard(services, opts, sp));
    }
    else
    {
        // Named pipeline — Task 2 fills this branch
        throw new NotImplementedException("Named pipelines arrive in Task 2.");
    }

    return services;
}

private static IAlertSink BuildAlertSink(SentinelOptions opts)
{
    IAlertSink raw = opts.AlertWebhook is not null
        ? new WebhookAlertSink(opts.AlertWebhook)
        : NullAlertSink.Instance;
    return new DeduplicatingAlertSink(
        new AlertSinkInstrumented(raw),
        opts.AlertDeduplicationWindow,
        opts.SessionIdleTimeout);
}

private static IAuditStore BuildAuditStore(SentinelOptions opts)
    => new AuditStoreInstrumented(new RingBufferAuditStore(opts.AuditCapacity));

private static InterventionEngine BuildInterventionEngine(SentinelOptions opts, IServiceProvider sp)
    => new(opts, mediator: sp.GetService<IMediator>(), logger: sp.GetService<ILogger<InterventionEngine>>());

private static IDetectionPipeline BuildDetectionPipeline(SentinelOptions opts, IServiceProvider sp)
    => new DetectionPipelineInstrumented(
        new DetectionPipeline(
            sp.GetServices<IDetector>(),
            opts.GetDetectorConfigurations(),
            opts.EscalationClient,
            sp.GetService<ILogger<DetectionPipeline>>()));

private static IToolCallGuard BuildToolCallGuard(IServiceCollection services, SentinelOptions opts, IServiceProvider sp)
{
    var hasSecurityContext = services.Any(d => d.ServiceType == typeof(ISecurityContext));
    var policyByName = new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal);
    foreach (var p in sp.GetServices<IAuthorizationPolicy>())
    {
        var attrs = p.GetType().GetCustomAttributes(typeof(AuthorizationPolicyAttribute), inherit: false);
        if (attrs.Length == 0) continue;
        var attr = (AuthorizationPolicyAttribute)attrs[0];
        policyByName[attr.Name] = p;
    }
    var bindings = opts.GetAuthorizationBindings();
    var logger = sp.GetService<ILogger<DefaultToolCallGuard>>();
    var pipelineLogger = sp.GetService<ILogger<SentinelPipeline>>();
    EmitAuthorizationStartupWarnings(opts, bindings, policyByName, hasSecurityContext, pipelineLogger);
    return new DefaultToolCallGuard(bindings, policyByName, opts.DefaultToolPolicy, logger);
}
```

The lambda factories for `BuildInterventionEngine`, `BuildDetectionPipeline`, `BuildToolCallGuard` keep the same `IServiceProvider`-driven shape as before — DI-time resolution is unchanged.

`RegisterUserDetectors` and `EmitAuthorizationStartupWarnings` (existing private helpers at lines 75-117) stay as-is.

### Step 3: Run all tests to verify zero behavior change

Run: `dotnet test AI.Sentinel.slnx --nologo -v minimal`

Expected: all 502 + 552 tests across all test projects pass on both TFMs. If anything breaks, the refactor introduced an unintended behavior change — investigate before proceeding.

### Step 4: Verify build cleanliness

Run: `dotnet build AI.Sentinel.slnx -c Debug --nologo -v minimal`

Expected: 0 warnings, 0 errors.

### Step 5: Commit

```bash
git add src/AI.Sentinel/ServiceCollectionExtensions.cs
git commit -m "refactor(detection): extract RegisterPipeline private helper from AddAISentinel"
```

Self-review: (1) zero behavior change verified by all tests still passing, (2) the `name is null` branch is functionally identical to the previous body, (3) the `name is not null` branch throws `NotImplementedException` (Task 2 fills it), (4) helper methods extracted are pure factories that match the original lambdas line-for-line.

---

## Task 2: Named `AddAISentinel(name, configure)` overload + keyed-DI registration

**Files:**
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs` — fill in the `name is not null` branch + add the public overload
- Create: `tests/AI.Sentinel.Tests/NamedPipelineTests.cs`

### Step 1: Add the public overload

In `ServiceCollectionExtensions.cs`, add a new public method above the existing `AddAISentinel`:

```csharp
/// <summary>Registers a named AI.Sentinel pipeline with isolated <see cref="SentinelOptions"/>,
/// <see cref="IDetectionPipeline"/>, and <see cref="InterventionEngine"/>. Audit store, forwarders,
/// and alert sink are shared with the default pipeline (and other named pipelines).
/// Resolve via <see cref="UseAISentinel(ChatClientBuilder, string)"/>.</summary>
/// <exception cref="ArgumentNullException">name is null.</exception>
/// <exception cref="ArgumentException">name is empty or whitespace.</exception>
/// <exception cref="InvalidOperationException">A pipeline with this name is already registered.</exception>
public static IServiceCollection AddAISentinel(
    this IServiceCollection services,
    string name,
    Action<SentinelOptions> configure)
{
    ArgumentNullException.ThrowIfNull(services);
    ArgumentNullException.ThrowIfNull(name);
    ArgumentNullException.ThrowIfNull(configure);
    if (string.IsNullOrWhiteSpace(name))
    {
        throw new ArgumentException("AI.Sentinel pipeline name must not be empty or whitespace.", nameof(name));
    }

    if (services.Any(d => d.IsKeyedService && d.ServiceKey is string k
        && string.Equals(k, name, StringComparison.Ordinal)
        && d.ServiceType == typeof(SentinelOptions)))
    {
        throw new InvalidOperationException($"AI.Sentinel pipeline '{name}' is already registered.");
    }

    return RegisterPipeline(services, name, configure);
}
```

### Step 2: Fill in the `name is not null` branch in `RegisterPipeline`

Replace the `throw new NotImplementedException(...)` from Task 1 with:

```csharp
else
{
    // Named pipeline — keyed singletons for SentinelOptions, IDetectionPipeline, InterventionEngine.
    // Audit/forwarder/alert/detector-pool/IToolCallGuard stay shared across all pipelines (registered
    // by the default unnamed AddAISentinel call, or absent if the user only registered named pipelines).
    services.AddKeyedSingleton(name, opts);
    services.AddKeyedSingleton(name, (sp, _) => BuildInterventionEngine(opts, sp));

    // Detectors must be registered before any IDetectionPipeline factory runs.
    // We can't call AddAISentinelDetectors / RegisterUserDetectors per-name (those mutate the GLOBAL
    // pool); we register them here ONLY if the default unnamed pipeline hasn't registered them yet
    // (idempotent behavior — registering official detectors twice is harmless because of
    // [Singleton(As=IDetector, AllowMultiple=true)] semantics, but we want one canonical
    // registration). User detectors from this named pipeline ARE registered globally.
    services.AddAISentinelDetectors();
    RegisterUserDetectors(services, opts);

    services.AddKeyedSingleton<IDetectionPipeline>(name, (sp, _) => BuildDetectionPipeline(opts, sp));
}
```

The keyed `AddKeyedSingleton(name, opts)` form (object-key + instance) registers the already-constructed `SentinelOptions`. The factory forms `(sp, _) => ...` for `InterventionEngine` and `IDetectionPipeline` defer construction until first resolve, preserving the v1.0 lifecycle.

Audit / forwarder / alert sink / `IToolCallGuard` are NOT registered in the named branch — they're either already registered by the default `AddAISentinel(services, configure)` call, or they need to be registered manually (a future caller-only refinement).

### Step 3: Create the test file scaffold

Create `tests/AI.Sentinel.Tests/NamedPipelineTests.cs`:

```csharp
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests;

public class NamedPipelineTests
{
    [Fact]
    public void AddAISentinel_NullName_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddAISentinel(name: null!, opts => { }));
    }

    [Fact]
    public void AddAISentinel_EmptyName_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AddAISentinel(name: "", opts => { }));
    }

    [Fact]
    public void AddAISentinel_WhitespaceName_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AddAISentinel(name: "   ", opts => { }));
    }

    [Fact]
    public void AddAISentinel_DuplicateName_ThrowsInvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddAISentinel("strict", opts => { });
        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddAISentinel("strict", opts => { }));
        Assert.Contains("strict", ex.Message, StringComparison.Ordinal);
        Assert.Contains("already registered", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddAISentinel_Named_RegistersIsolatedSentinelOptions()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);  // default unnamed
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 200);
        services.AddAISentinel("lenient", opts => opts.AuditCapacity = 300);

        var sp = services.BuildServiceProvider();
        var defaultOpts = sp.GetRequiredService<SentinelOptions>();
        var strictOpts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
        var lenientOpts = sp.GetRequiredKeyedService<SentinelOptions>("lenient");

        Assert.Equal(100, defaultOpts.AuditCapacity);
        Assert.Equal(200, strictOpts.AuditCapacity);
        Assert.Equal(300, lenientOpts.AuditCapacity);
        Assert.NotSame(defaultOpts, strictOpts);
        Assert.NotSame(strictOpts, lenientOpts);
    }

    [Fact]
    public void AddAISentinel_Named_DefaultPipelineUnaffected()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);

        var sp = services.BuildServiceProvider();
        Assert.Equal(100, sp.GetRequiredService<SentinelOptions>().AuditCapacity);
        Assert.NotNull(sp.GetRequiredService<IDetectionPipeline>());
    }
}
```

### Step 4: Run the tests

Run: `dotnet test tests/AI.Sentinel.Tests --nologo -v minimal --filter "FullyQualifiedName~NamedPipelineTests"`

Expected: 6 tests pass on both net8.0 and net10.0.

### Step 5: Run the full suite to confirm no regressions

Run: `dotnet test AI.Sentinel.slnx --nologo -v minimal`

Expected: all v1.0 tests + Configure<T> + 6 new = 508 in `AI.Sentinel.Tests`. Other test projects unchanged.

### Step 6: Commit

```bash
git add src/AI.Sentinel/ServiceCollectionExtensions.cs \
        tests/AI.Sentinel.Tests/NamedPipelineTests.cs
git commit -m "feat(detection): named AddAISentinel(name, configure) overload — keyed-DI registration"
```

Self-review: (1) name validation throws the right exception types in the right order (null → ANE, whitespace → AE, duplicate → IOE), (2) keyed singletons resolve correctly, (3) default unnamed pipeline still works alongside named, (4) audit store / IToolCallGuard not registered in the named branch (relies on default registration or absence).

---

## Task 3: Named `UseAISentinel(name)` overload + per-pipeline-feature tests

**Files:**
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs` — add the named `UseAISentinel(name)` overload
- Modify: `tests/AI.Sentinel.Tests/NamedPipelineTests.cs` — add 6 more tests

### Step 1: Add the named `UseAISentinel(name)` overload

In `ServiceCollectionExtensions.cs`, add a new method below the existing `UseAISentinel`:

```csharp
/// <summary>Resolves a named AI.Sentinel pipeline previously registered via
/// <see cref="AddAISentinel(IServiceCollection, string, Action{SentinelOptions})"/>.
/// Throws <see cref="InvalidOperationException"/> at chat client construction time if
/// no pipeline with this name was registered.</summary>
public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder, string name) =>
    builder.Use((inner, sp) =>
    {
        ArgumentNullException.ThrowIfNull(name);

        var opts = sp.GetRequiredKeyedService<SentinelOptions>(name);
        var pipeline = sp.GetRequiredKeyedService<IDetectionPipeline>(name);
        var engine = sp.GetRequiredKeyedService<InterventionEngine>(name);

        if (opts.EmbeddingGenerator is null)
        {
            var logger = sp.GetService<ILogger<SentinelPipeline>>();
            var semanticCount = sp.GetServices<IDetector>().Count(d => d is SemanticDetectorBase);
            logger?.LogWarning(
                "AI.Sentinel pipeline '{Name}': EmbeddingGenerator is not configured. All {Count} semantic detectors will return Clean until an IEmbeddingGenerator is provided.",
                name, semanticCount);
        }

        return new SentinelChatClient(
            inner,
            pipeline,
            sp.GetRequiredService<IAuditStore>(),     // shared
            engine,
            opts,
            sp.GetRequiredService<IAlertSink>(),      // shared
            sp.GetServices<IAuditForwarder>());       // shared
    });
```

The shared services (`IAuditStore`, `IAlertSink`, `IAuditForwarder`) are resolved unkeyed — they come from the default `AddAISentinel(...)` call.

### Step 2: Add the 6 selection / per-pipeline-feature tests

Add to `NamedPipelineTests.cs`:

```csharp
[Fact]
public async Task UseAISentinel_NamedResolvesKeyedPipeline()
{
    var services = new ServiceCollection();
    services.AddSingleton<IMediator>(sp => null!);  // optional dependency
    services.AddAISentinel(opts => opts.AuditCapacity = 100);
    services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);

    var sp = services.BuildServiceProvider();
    // We don't actually invoke the chat client — we just verify the keyed services resolve.
    var opts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
    var pipeline = sp.GetRequiredKeyedService<IDetectionPipeline>("strict");
    var engine = sp.GetRequiredKeyedService<InterventionEngine>("strict");

    Assert.Equal(999, opts.AuditCapacity);
    Assert.NotNull(pipeline);
    Assert.NotNull(engine);
}

[Fact]
public void UseAISentinel_UnknownName_FailsToResolveKeyedService()
{
    var services = new ServiceCollection();
    services.AddAISentinel(opts => { });  // default only
    var sp = services.BuildServiceProvider();

    Assert.Throws<InvalidOperationException>(() =>
        sp.GetRequiredKeyedService<IDetectionPipeline>("never-registered"));
}

[Fact]
public void UseAISentinel_UnnamedStillResolvesDefaultPipeline()
{
    var services = new ServiceCollection();
    services.AddAISentinel(opts => opts.AuditCapacity = 42);
    services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);
    var sp = services.BuildServiceProvider();

    Assert.Equal(42, sp.GetRequiredService<SentinelOptions>().AuditCapacity);
}

[Fact]
public void Named_ConfigureT_AppliesPerPipeline()
{
    var services = new ServiceCollection();
    services.AddAISentinel(opts => { });
    services.AddAISentinel("strict", opts =>
        opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High));
    services.AddAISentinel("lenient", opts =>
        opts.Configure<JailbreakDetector>(c => c.Enabled = false));

    var sp = services.BuildServiceProvider();
    var strictOpts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
    var lenientOpts = sp.GetRequiredKeyedService<SentinelOptions>("lenient");

    var strictCfg = strictOpts.GetDetectorConfigurations()[typeof(JailbreakDetector)];
    var lenientCfg = lenientOpts.GetDetectorConfigurations()[typeof(JailbreakDetector)];

    Assert.Equal(Severity.High, strictCfg.SeverityFloor);
    Assert.True(strictCfg.Enabled);  // strict didn't disable
    Assert.Null(lenientCfg.SeverityFloor);
    Assert.False(lenientCfg.Enabled);  // lenient disabled

    // Default has no configuration for JailbreakDetector
    var defaultOpts = sp.GetRequiredService<SentinelOptions>();
    Assert.False(defaultOpts.GetDetectorConfigurations().ContainsKey(typeof(JailbreakDetector)));
}

[Fact]
public void Named_AuditStoreIsShared()
{
    var services = new ServiceCollection();
    services.AddAISentinel(opts => { });
    services.AddAISentinel("strict", opts => { });
    services.AddAISentinel("lenient", opts => { });

    var sp = services.BuildServiceProvider();
    var defaultStore = sp.GetRequiredService<IAuditStore>();
    // No keyed audit store should exist — the keyed lookup throws.
    Assert.Throws<InvalidOperationException>(() => sp.GetRequiredKeyedService<IAuditStore>("strict"));
    Assert.Throws<InvalidOperationException>(() => sp.GetRequiredKeyedService<IAuditStore>("lenient"));
    Assert.NotNull(defaultStore);  // single shared instance
}

[Fact]
public void Named_InterventionEngineIsolated()
{
    var services = new ServiceCollection();
    services.AddAISentinel(opts => opts.OnHigh = SentinelAction.Log);
    services.AddAISentinel("strict", opts => opts.OnHigh = SentinelAction.Quarantine);

    var sp = services.BuildServiceProvider();
    var defaultEngine = sp.GetRequiredService<InterventionEngine>();
    var strictEngine = sp.GetRequiredKeyedService<InterventionEngine>("strict");

    Assert.NotSame(defaultEngine, strictEngine);  // each pipeline has its own engine
}
```

### Step 3: Run all tests

Run: `dotnet test AI.Sentinel.slnx --nologo -v minimal`

Expected: 12 tests in `NamedPipelineTests` (6 from Task 2 + 6 new) + previous baselines = 514 in `AI.Sentinel.Tests` (502 + 12 new total). Other test projects unchanged.

### Step 4: Commit

```bash
git add src/AI.Sentinel/ServiceCollectionExtensions.cs \
        tests/AI.Sentinel.Tests/NamedPipelineTests.cs
git commit -m "feat(detection): named UseAISentinel(name) — chat client picks named pipeline at construction"
```

Self-review: (1) named resolution flows through `sp.GetRequiredKeyedService<T>(name)`, (2) shared services resolve unkeyed (audit, forwarders, alerts), (3) `Configure<T>` per pipeline truly isolated (test 4 verifies), (4) embedding-generator-missing warning includes the pipeline name.

---

## Task 4: README + BACKLOG cleanup + e2e smoke through `SentinelChatClient`

**Files:**
- Modify: `README.md` — add a "Named pipelines" section after the existing AddAISentinel quick start
- Modify: `docs/BACKLOG.md` — remove "Per-pipeline configuration" row
- Modify: `tests/AI.Sentinel.Tests/NamedPipelineTests.cs` — add 1 e2e smoke

### Step 1: Add the e2e smoke test

This validates that the named pipeline plumbing actually works end-to-end through `SentinelChatClient` (not just DI resolution). Mirror the e2e smoke pattern from `tests/AI.Sentinel.Tests/Detection/PipelineDetectorConfigTests.cs:241-275` (the e2e from the just-shipped Configure<T> feature).

Add to `NamedPipelineTests.cs`:

```csharp
private sealed class AlwaysFiringHighDetector : IDetector
{
    private static readonly DetectorId _id = new("E2E-NAMED-01");
    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;
    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High, "e2e fired"));
}

private sealed class NoopChatClient : IChatClient
{
    public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));
    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();
    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}

[Fact]
public async Task EndToEnd_NamedPipelineRoutesThroughSentinelChatClient()
{
    var services = new ServiceCollection();
    services.AddAISentinel(opts =>
    {
        opts.AddDetector<AlwaysFiringHighDetector>();
        opts.OnHigh = SentinelAction.Log;
    });
    services.AddAISentinel("strict", opts =>
    {
        opts.OnHigh = SentinelAction.Log;
        opts.Configure<AlwaysFiringHighDetector>(c => c.SeverityCap = Severity.Low);
    });

    services.AddChatClient(builder =>
        builder.UseAISentinel("strict").Use(new NoopChatClient()));

    var sp = services.BuildServiceProvider();
    var client = sp.GetRequiredService<IChatClient>();

    await client.GetResponseAsync(new List<ChatMessage> { new(ChatRole.User, "hi") });

    var store = sp.GetRequiredService<IAuditStore>();
    var entries = new List<AuditEntry>();
    await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
    {
        entries.Add(e);
    }

    // Strict pipeline applied SeverityCap = Low to the Always-High firing.
    Assert.Contains(entries, e =>
        string.Equals(e.DetectorId, "E2E-NAMED-01", StringComparison.Ordinal)
        && e.Severity == Severity.Low);
}
```

This test:
- Registers default + named "strict" pipelines
- The default has the detector firing High; "strict" has it Cap=Low
- Builds a chat client wired to "strict" via `UseAISentinel("strict")`
- Verifies the audit (shared store) shows the cap-applied severity, proving the named pipeline's `_configurations` flowed end-to-end

### Step 2: Update main `README.md`

Find the section in `README.md` that documents the basic `services.AddAISentinel(opts => ...)` pattern. Add a new subsection after it:

```markdown
### Named pipelines

Register multiple isolated pipelines under string names; pick one per chat client at
construction time. Useful for multi-LLM-endpoint apps and dev/staging/prod tier configurations.

\`\`\`csharp
// Default + two named variants
services.AddAISentinel(opts => opts.EmbeddingGenerator = realGen);
services.AddAISentinel("strict", opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
});
services.AddAISentinel("lenient", opts =>
{
    opts.OnCritical = SentinelAction.Log;
    opts.Configure<RepetitionLoopDetector>(c => c.Enabled = false);
});

// Pick one per chat client
services.AddChatClient("openai-strict", b =>
    b.UseAISentinel("strict").Use(new OpenAIChatClient(...)));
services.AddChatClient("openai-lenient", b =>
    b.UseAISentinel("lenient").Use(new OpenAIChatClient(...)));
\`\`\`

Each named pipeline gets its own `SentinelOptions`, `IDetectionPipeline`, and `InterventionEngine`.
The audit store, forwarders, and alert sink are shared — operational dashboards see all pipelines
through one feed. User-added detectors via `opts.AddDetector<T>()` register globally; per-pipeline
detector tuning rides on `opts.Configure<T>(c => ...)`.

Each named pipeline starts from a fresh `SentinelOptions()` — no inheritance from the default.
For shared base config, extract a helper:

\`\`\`csharp
Action<SentinelOptions> baseCfg = opts => opts.EmbeddingGenerator = realGen;
services.AddAISentinel(baseCfg);
services.AddAISentinel("strict", opts => { baseCfg(opts); opts.OnCritical = SentinelAction.Quarantine; });
\`\`\`
```

(Replace each `\`\`\`` with real triple-backticks in the actual file.)

### Step 3: Update `docs/BACKLOG.md`

Find the row in the Architecture / Integration table:

```markdown
| **Per-pipeline configuration** | Register multiple named `SentinelOptions` instances so different endpoints get different detector sets, thresholds, or `EscalationClient`s |
```

**Remove** that row entirely. Phase B (request-time selector + per-name audit isolation) lives only in the design doc — don't preemptively add it to BACKLOG until a real user surfaces the need.

### Step 4: Run all tests + sanity build

```bash
dotnet test AI.Sentinel.slnx --nologo -v minimal
dotnet build AI.Sentinel.slnx -c Debug --nologo -v minimal
```

Expected:
- `AI.Sentinel.Tests`: 515 (502 + 12 + 1 e2e)
- All other test projects unchanged
- 0 warnings, 0 errors

Pre-existing flake: `BufferingAuditForwarderTests.SizeThreshold_FlushesBatch` and `PipelineForwarderIntegrationTests.SlowForwarder_DoesNotBlockPipeline` (timing flakes on net8.0). Pass on rerun. Don't fix.

### Step 5: Commit

```bash
git add README.md docs/BACKLOG.md tests/AI.Sentinel.Tests/NamedPipelineTests.cs
git commit -m "docs+test(detection): named pipelines README + e2e smoke + backlog cleanup"
```

Self-review: (1) README has a worked named-pipeline example, (2) BACKLOG row removed, (3) e2e smoke validates the keyed-DI flow through `SentinelChatClient`, (4) build is 0/0 and all test projects pass.

---

## Final review checklist

After Task 4, dispatch the `superpowers:code-reviewer` agent for cross-cutting review against:

- The design doc at [docs/plans/2026-04-28-per-pipeline-config-design.md](2026-04-28-per-pipeline-config-design.md)
- This plan
- Existing AI.Sentinel conventions (MA0002/MA0006 ordinal-string, no XML doc noise, public/internal split, `[InternalsVisibleTo]` patterns)
- All decisions from the design (Q1 DI-time only, Q2 shared audit, Q3 string keys, independence rule, detector pool global)

Then run `superpowers:finishing-a-development-branch`.

**Total estimated scope:** ~150 LOC implementation, ~300 LOC tests, 4 tasks, 12 unit tests + 1 e2e smoke, no new NuGet package. Should land in 1.5-2 hours of focused work.
