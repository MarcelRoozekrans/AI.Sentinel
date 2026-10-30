---
sidebar_position: 1
title: Named pipelines
---

# Named pipelines

Register multiple isolated AI.Sentinel pipelines under string names; pick one per chat client at construction time. Useful for multi-LLM-endpoint apps and dev/staging/prod tier configurations.

## Why named pipelines

A single `services.AddAISentinel(opts => ...)` call wires *one* `SentinelOptions`, *one* `IDetectionPipeline`, and *one* `InterventionEngine` as DI singletons. That's fine until you need:

- **Different actions per environment** — dev allows pass-through; prod quarantines
- **Different detector tuning per endpoint** — strict for customer-facing chat, lenient for internal RAG
- **Per-tier escalation policies** — paying tier gets LLM escalation, free tier doesn't

Named pipelines let you register multiple isolated configurations and select one at chat-client construction time.

## Basic usage

```csharp
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
```

## What's isolated, what's shared

| Component | Per-name | Shared (default) |
|---|:---:|:---:|
| `SentinelOptions` | ✓ | |
| `IDetectionPipeline` | ✓ | |
| `InterventionEngine` | ✓ | |
| `IAuditStore` | | ✓ |
| `IAuditForwarder[]` | | ✓ |
| `IAlertSink` | | ✓ |
| Detector pool (`IDetector`s) | | ✓ |
| Embedding generator and caches used by semantic detectors | ✓ (when set) | ✓ (inherited) |
| `IToolCallGuard` | | ✓ |

Audit infrastructure is **shared** across all pipelines so operational dashboards see all pipelines through one feed. User-added detectors via `opts.AddDetector<T>()` register globally; per-pipeline detector tuning rides on `opts.Configure<T>(c => ...)`.

The detector instances are shared, but the embedding generator and caches belong to the pipeline running the scan. A named pipeline can set its own `EmbeddingGenerator`, `EmbeddingCache` and `ExampleEmbeddingCache`; what it leaves unset follows the default pipeline. The generator and the caches move as one unit, so a named pipeline never reads the default's caches with a generator other than the default's:

| Named pipeline sets | Generator | Scan cache | Example cache |
|---|---|---|---|
| a generator | its own | its own if set, otherwise a fresh in-memory cache | its own if set, otherwise none |
| no generator | the default pipeline's | its own if set, otherwise the default's | its own if set, otherwise the default's |

"The default pipeline's generator" is the one set on the unnamed `AddAISentinel(...)` options, or else the `IEmbeddingGenerator<string, Embedding<float>>` registered in DI, for example with `services.AddEmbeddingGenerator(...)`, unless the default options set `UseEmbeddingGeneratorFromServices = false`. A named pipeline's own `UseEmbeddingGeneratorFromServices` adds no container lookup: without a generator of its own it inherits the default's. A keyed generator registered under a pipeline's name, as `AddKeyedEmbeddingGenerator` does, is not used; set `EmbeddingGenerator` on the pipeline's options instead.

Each pipeline embeds the texts of a scan once, with its own generator, however many semantic detectors it runs; see [Embedding cache](./embedding-cache). Two pipelines that share a generator instance also share its example-phrase vectors. Vectors from different generators are never compared with each other, as long as you do not set the same `EmbeddingCache` or `ExampleEmbeddingCache` instance on two pipelines with different generators: the caches are keyed by text alone, so a shared instance would hand one generator's vectors to the other.

The unused-generator warning is judged per pipeline on its effective generator: a named pipeline that sets its own generator is not reported, and one that sets none inherits the default's.

## Default + named coexist

The unnamed `services.AddAISentinel(opts => ...)` registers the **default** pipeline with unkeyed singletons. Named registrations use **keyed** singletons (`AddKeyedSingleton(name, ...)`).

`.UseAISentinel()` (no name) resolves the unkeyed default — full v1.0 backward compatibility. `.UseAISentinel("name")` resolves the keyed named pipeline. They coexist cleanly.

## No inheritance from the default

Each named pipeline starts from a **fresh `SentinelOptions()`** — no inheritance. If you want shared base config across multiple named pipelines, extract a helper:

```csharp
Action<SentinelOptions> baseCfg = opts =>
{
    opts.EmbeddingGenerator = realGen;
    opts.AuditCapacity = 50_000;
};

services.AddAISentinel(baseCfg);
services.AddAISentinel("strict", opts =>
{
    baseCfg(opts);
    opts.OnCritical = SentinelAction.Quarantine;
});
services.AddAISentinel("lenient", opts =>
{
    baseCfg(opts);
    opts.OnCritical = SentinelAction.Log;
});
```

This is intentional: avoids the surprise of "I changed the default and now strict suddenly behaves differently."

## Validation rules

| Input | Behavior |
|---|---|
| `AddAISentinel(name: null, ...)` | Throws `ArgumentNullException` |
| `AddAISentinel(name: "", ...)` or whitespace | Throws `ArgumentException` |
| `AddAISentinel("name", ...)` for an already-registered name | Throws `InvalidOperationException` |
| A second default `AddAISentinel(...)` on the same `IServiceCollection` | Throws `InvalidOperationException` ("The default AI.Sentinel pipeline is already registered."). Call it once, in the composition root |
| `.UseAISentinel("never-registered")` | Throws `InvalidOperationException` at chat-client construction time (first request resolution) |
| `.UseAISentinel("name")` when `IAuditStore` etc. are unregistered | Throws `InvalidOperationException` with a clear message pointing at the missing default |

## Phase A limitations

These are intentional v1 scope choices, not bugs. Each is captured on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) for Phase B.

### 1. Always register the default unnamed `AddAISentinel(...)` first

The shared audit store, forwarders, alert sink, and tool-call guard are wired by the default call. Skipping it and registering only named pipelines causes the named chat client to throw a missing-shared-infrastructure error the first time it's resolved.

```csharp
// ❌ Won't work — no default registered
services.AddAISentinel("strict", opts => /* ... */);
services.AddChatClient(b => b.UseAISentinel("strict").Use(new ...));
// → InvalidOperationException at first request: "shared infrastructure (IAuditStore, IAlertSink, IAuditForwarder) is missing"

// ✓ Always register the default first
services.AddAISentinel(opts => { /* defaults or shared base config */ });
services.AddAISentinel("strict", opts => /* per-name overrides */);
services.AddChatClient(b => b.UseAISentinel("strict").Use(new ...));
```

### 2. Tool-call authorization is global, not per-name

`opts.RequireToolPolicy(...)` calls on named pipelines are **silently ignored** — only the default pipeline's bindings are consulted by `IToolCallGuard`. Configure tool policies on the default pipeline for now. Per-name auth bindings are a Phase B feature.

### 3. No request-time selector

The pipeline is fixed at chat-client construction time. Multi-tenant routing where the tenant ID arrives with the request requires Phase B. Today, register one chat client per named pipeline and route at the host level (different chat client per tenant resolution).

## Common patterns

### Multi-environment

```csharp
services.AddAISentinel(opts => opts.EmbeddingGenerator = realGen);  // base config
services.AddAISentinel("dev",     opts => opts.OnCritical = SentinelAction.Log);
services.AddAISentinel("staging", opts => opts.OnCritical = SentinelAction.Alert);
services.AddAISentinel("prod",    opts => opts.OnCritical = SentinelAction.Quarantine);

var env = builder.Configuration["AISentinel:Tier"];  // "dev" / "staging" / "prod"
services.AddChatClient(b => b.UseAISentinel(env).Use(new OpenAIChatClient(...)));
```

### Multi-endpoint (different LLMs, same severity policy)

```csharp
services.AddAISentinel(opts => opts.OnHigh = SentinelAction.Alert);

services.AddChatClient("openai", b => b.UseAISentinel().Use(new OpenAIChatClient(...)));
services.AddChatClient("anthropic", b => b.UseAISentinel().Use(new AnthropicChatClient(...)));
// Both share the default pipeline. Same detection, same intervention, same audit.
```

### Per-tier (paying tier gets LLM escalation)

```csharp
services.AddAISentinel(opts => opts.EmbeddingGenerator = realGen);  // the free and paying tiers inherit this generator
services.AddAISentinel("free", opts =>
{
    // No EscalationClient — LLM-escalation detectors no-op
});
services.AddAISentinel("paying", opts =>
{
    opts.EscalationClient = upgradeClient;   // LLM second-pass classifier
});

services.AddChatClient("free-tier", b => b.UseAISentinel("free").Use(new ...));
services.AddChatClient("paying-tier", b => b.UseAISentinel("paying").Use(new ...));
```

## Next: [Fluent per-detector config](./fluent-config) — disable / clamp individual detectors per pipeline
