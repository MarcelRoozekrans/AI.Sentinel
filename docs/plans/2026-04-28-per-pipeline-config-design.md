# Per-pipeline configuration (Phase A) — design

**Status:** approved 2026-04-28
**Closes backlog item:** "Per-pipeline configuration" (Architecture / Integration table)
**Builds on:** [Fluent per-detector config design](2026-04-28-fluent-detector-config-design.md) — uses `Configure<T>` for per-name detector tuning

## Goal

Operators register multiple isolated AI.Sentinel pipelines under string names; chat
clients select one at construction time via `.UseAISentinel("name")`. Each named
pipeline has its own `SentinelOptions`, `IDetectionPipeline`, and `InterventionEngine`;
audit infrastructure (store, forwarders, alert sink) is shared.

```csharp
services.AddAISentinel(opts => opts.EmbeddingGenerator = realGen);     // default (unnamed)
services.AddAISentinel("strict", opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.OnHigh     = SentinelAction.Quarantine;
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
});
services.AddAISentinel("lenient", opts =>
{
    opts.OnCritical = SentinelAction.Log;
    opts.Configure<RepetitionLoopDetector>(c => c.Enabled = false);
});

services.AddChatClient("openai-strict", b =>
    b.UseAISentinel("strict").Use(new OpenAIChatClient(...)));
services.AddChatClient("openai-lenient", b =>
    b.UseAISentinel("lenient").Use(new OpenAIChatClient(...)));
```

Lives in core `AI.Sentinel`. Pure addition — no breaking changes, default unnamed
pipeline keeps its current shape and behavior.

## Scope

**In scope (Phase A — DI-time named pipelines):**
- New overload `AddAISentinel(this IServiceCollection, string name, Action<SentinelOptions>)`
- New overload `UseAISentinel(this ChatClientBuilder, string name)`
- Keyed-services wiring for `SentinelOptions`, `IDetectionPipeline`, `InterventionEngine` per name
- ~12 unit tests + 1 e2e smoke
- README "Named pipelines" section + BACKLOG cleanup

**Out of scope (Phase B — deferred until a real user request):**
- Request-time selector (`Func<RequestContext, string>`) — handles multi-tenant SaaS where the tenant ID arrives with the request
- Per-name audit store / forwarders / alert sink — multi-tenant audit isolation is a Phase B concern
- Detector pool isolation per name — `Configure<T>` already gives per-name detector customization (Enabled/Floor/Cap)
- Inheritance from default — each named pipeline starts fresh; users extract a helper if they want shared base config

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Q1 — When does selection happen | **DI-time only** (Phase A); request-time selector accretes per real user request | Solves multi-LLM-endpoint and dev/staging/prod cleanly. Phase B (request-time) needs a concrete user request to design against — it touches every detector lookup. |
| Q2 — Audit infrastructure isolation | **Shared** (one `IAuditStore`, one forwarder set, one alert sink) | "Different LLM endpoints" use case wants ONE audit feed for the operations team. Multi-tenant audit isolation is a Phase B concern bundled with the request-time selector. Per-name overrides would bloat the registration API for 5% of users. |
| Q3 — Name keying | **String** | Matches ASP.NET conventions (named options, named HTTP clients). Composes with config-file-driven per-environment names. Works for eventual Phase B where tenant IDs are runtime data. |
| Independence | **Each named pipeline starts from a fresh `SentinelOptions()`** — no inheritance from the default | Avoids the surprise of "I changed the default and now strict suddenly has different behavior." Users who want shared base config extract a helper. |
| Detector pool | **Globally registered** (existing source-gen pattern unchanged) | Per-name customization rides on `Configure<T>` from the just-shipped feature. No new detector-registration ceremony. |
| Default + named coexistence | **Both work; default uses unkeyed DI, named uses keyed DI** | Full backward compat — `UseAISentinel()` (no name) keeps resolving the unkeyed singleton. |

## Public API

```csharp
namespace AI.Sentinel;

public static class ServiceCollectionExtensions
{
    // Existing — unchanged. Default (unnamed) pipeline.
    public static IServiceCollection AddAISentinel(
        this IServiceCollection services,
        Action<SentinelOptions> configure);

    // NEW — registers a named pipeline with isolated SentinelOptions/IDetectionPipeline/InterventionEngine.
    // Throws ArgumentException on empty/whitespace name; ArgumentNullException on null name;
    // InvalidOperationException if "name" is already registered.
    public static IServiceCollection AddAISentinel(
        this IServiceCollection services,
        string name,
        Action<SentinelOptions> configure);
}

public static class ChatClientBuilderExtensions
{
    // Existing — unchanged. Resolves the default (unnamed) pipeline.
    public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder);

    // NEW — resolves the pipeline registered under "name".
    // Throws InvalidOperationException at chat client construction time if no such name exists.
    public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder, string name);
}
```

## DI mechanics (.NET 8+ keyed services)

- Default registration uses the existing unkeyed singletons (`AddSingleton<IDetectionPipeline>`, etc.).
- Named registration uses `services.AddKeyedSingleton<IDetectionPipeline>(name, factory)` etc.
- `.UseAISentinel("name")` resolves via `sp.GetRequiredKeyedService<IDetectionPipeline>(name)`.
- Audit store, forwarders, alert sink stay unkeyed (shared per Q2).

The existing `AddAISentinel(services, Action<SentinelOptions>)` becomes a thin wrapper over a private `RegisterPipeline(services, name, configure)` helper. The default call passes `name = null` (or `Options.DefaultName`); the named call passes the user's name. The helper:

1. Validates the name (null/empty/whitespace check applies only to the named overload).
2. Constructs a fresh `SentinelOptions()` and runs the configure lambda.
3. Registers `SentinelOptions`, `IDetectionPipeline`, `InterventionEngine` either as unkeyed singletons (default path) or keyed singletons (named path).
4. Detector pool, audit store, forwarders, alert sink registration is unchanged.

## `UseAISentinel(name)` resolution

```csharp
public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder, string name) =>
    builder.Use((inner, sp) =>
    {
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

The existing unnamed `UseAISentinel()` keeps its current implementation — the keyed/unkeyed split keeps behavior identical for v1.0 callers.

## Error handling

- `AddAISentinel(services, null, configure)` → `ArgumentNullException`
- `AddAISentinel(services, "", configure)` or whitespace-only → `ArgumentException`
- `AddAISentinel(services, "name", configure)` for an already-registered name → `InvalidOperationException("AI.Sentinel pipeline 'name' is already registered.")`
- `.UseAISentinel("name")` resolving an unknown name → `InvalidOperationException` from `sp.GetRequiredKeyedService` at chat client construction time

## Tests

In `tests/AI.Sentinel.Tests/`:

1. `AddAISentinel_Named_RegistersIsolatedSentinelOptions` — two named pipelines have distinct option values
2. `AddAISentinel_Named_RegistersIsolatedDetectionPipeline` — each pipeline applies its own `Configure<T>` settings
3. `AddAISentinel_Named_DefaultPipelineUnaffected` — register named + default; default still resolves cleanly
4. `AddAISentinel_DuplicateName_ThrowsInvalidOperationException`
5. `AddAISentinel_EmptyOrWhitespaceName_ThrowsArgumentException`
6. `AddAISentinel_NullName_ThrowsArgumentNullException`
7. `UseAISentinel_NamedResolvesKeyedPipeline` — chat client uses the right named pipeline
8. `UseAISentinel_UnknownName_ThrowsAtConstruction`
9. `UseAISentinel_UnnamedStillResolvesDefaultPipeline` — v1.0 backward compat
10. `Named_ConfigureT_AppliesPerPipeline` — `Configure<JailbreakDetector>` on "strict" doesn't affect "lenient"
11. `Named_AuditStoreIsShared` — `sp.GetRequiredService<IAuditStore>()` returns the same instance regardless of pipeline
12. `Named_EmbeddingGeneratorMissing_LogsWarningWithName` — warning message includes the pipeline name

Plus an e2e smoke through `SentinelChatClient`: two named pipelines with different `OnCritical` actions, two chat clients via `.UseAISentinel("strict")` / `.UseAISentinel("lenient")`, verify strict quarantines while lenient logs.

## Documentation

- Main `README.md`: brief "Named pipelines" section after the existing `AddAISentinel` quick start, with the worked multi-endpoint example.
- `docs/BACKLOG.md`: remove "Per-pipeline configuration" row from the Architecture / Integration table.
- No follow-up items added unless review surfaces them.

## Risk / open questions

- **Risk:** users register a named pipeline but call `.UseAISentinel()` (no name) and silently get the default. Mitigation: clear errors in the unknown-name path (the dual goes the other way — name-not-found throws); documentation emphasizes the name + `UseAISentinel(name)` must match.
- **Risk:** users assume named pipelines inherit from the default and are surprised when changes to the default don't propagate. Mitigation: documentation explicitly states each named pipeline starts from a fresh `SentinelOptions()`; provide the "extract a helper" pattern.
- **No open questions.** Q1–Q3, isolation scope, independence rules, error semantics all settled.

## Estimated scope

~150 LOC implementation + ~300 LOC tests, 4 tasks, 12 unit tests + 1 e2e smoke, no new package. ~1.5 days of focused work.

## Phase B placeholder (not in scope)

When a real multi-tenant case surfaces, Phase B adds:
- `services.AddAISentinel(Func<IServiceProvider, RequestContext, string> selector)` — runtime selector
- A new `INamedPipelineSelector` service that the `SentinelChatClient` middleware queries per request
- Optional per-name audit isolation (`AddAISentinel("name", opts, audit: ...)` overrides)

These are not designed yet — Phase A is the foundation; Phase B is a separate design exercise.
