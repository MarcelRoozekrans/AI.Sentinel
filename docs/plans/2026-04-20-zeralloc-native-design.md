# ZeroAlloc Native Integration Design

**Date:** 2026-04-20
**Status:** Approved

## Goal

Integrate the ZeroAlloc package suite natively into AI.Sentinel — not as optional add-ons but as first-class dependencies that shape the public API. Breaking changes are acceptable; the library is not yet live.

## Scope

Three integrations, in priority order:

1. `ZeroAlloc.Results` — Results-first detection pipeline
2. `ZeroAlloc.Inject` — Compile-time detector registration
3. `ZeroAlloc.Rest` — Optional webhook alert sink

`ZeroAlloc.Cache` is explicitly out of scope. Caching detector results is unsafe for session-aware detectors (those reading `ctx.Messages` or `ctx.History`), and the LLM-escalating stubs that would benefit most are cheap until they escalate. Revisit when there is a concrete perf case.

---

## 1. ZeroAlloc.Results

### Decision

Results propagate all the way out to the caller. `SentinelPipeline` is the primary entry point with a clean `Result<ChatResponse, SentinelError>` return type. `SentinelChatClient` is a thin compatibility shim for callers constrained to `IChatClient`.

### SentinelError

```csharp
public abstract record SentinelError
{
    public sealed record ThreatDetected(DetectionResult Result, SentinelAction Action) : SentinelError;
    public sealed record PipelineFailure(string Message, Exception? Inner = null) : SentinelError;
}
```

### SentinelPipeline (new primary class)

```csharp
public sealed class SentinelPipeline
{
    public ValueTask<Result<ChatResponse, SentinelError>> GetResponseAsync(
        IList<ChatMessage> messages,
        ChatOptions? options,
        CancellationToken ct);

    public IAsyncEnumerable<Result<StreamingChatCompletionUpdate, SentinelError>> GetStreamingResponseAsync(
        IList<ChatMessage> messages,
        ChatOptions? options,
        CancellationToken ct);
}
```

`SentinelPipeline` owns the detection + intervention logic currently in `SentinelChatClient`. It never throws; all error paths return `Result.Failure(SentinelError)`.

### SentinelChatClient (thin shim)

```csharp
public sealed class SentinelChatClient : DelegatingChatClient
{
    private readonly SentinelPipeline _pipeline;

    public override async Task<ChatResponse> GetResponseAsync(...) =>
        (await _pipeline.GetResponseAsync(messages, options, ct))
            .Match(ok => ok, err => throw err.ToException());
}
```

`SentinelException` remains for IChatClient callers. `ToException()` is an extension on `SentinelError`.

### DetectionResult

No change. `DetectionResult` is already a clean value type. The `Result<T,E>` wrapper lives in `SentinelPipeline`, not inside individual detectors.

---

## 2. ZeroAlloc.Inject

### Problem

`ServiceCollectionExtensions.cs` currently has 43 explicit `AddSingleton<IDetector, XxxDetector>()` lines split across three methods to satisfy the MA0051 line limit. Every new detector requires a manual edit.

### Solution

Each detector declares its own registration via an attribute:

```csharp
[Register(typeof(IDetector), Lifetime.Singleton)]
public sealed partial class PromptInjectionDetector : IDetector { ... }
```

`ServiceCollectionExtensions` calls a single source-generated method:

```csharp
services.AddGeneratedRegistrations();
```

New detectors self-register. No manual wiring, no MA0051 pressure on the extensions class.

### Migration

Add `[Register(typeof(IDetector), Lifetime.Singleton)]` to all 43 detector files (mechanical, one-time). Remove the three explicit registration methods from `ServiceCollectionExtensions`.

---

## 3. ZeroAlloc.Rest

### Problem

`InterventionEngine` publishes `ThreatDetectedNotification` via `ZeroAlloc.Mediator` for in-process subscribers, but there is no built-in path to push alerts to external systems (Slack, SIEM, webhooks).

### Solution

`SentinelOptions` gains an optional webhook endpoint:

```csharp
options.AlertWebhook = new Uri("https://hooks.slack.com/...");
```

`InterventionEngine` receives an injected `IAlertSink` (sourced from `ZeroAlloc.Rest`). On `Quarantine` or `Alert` actions it fires a POST with a serialized `SentinelError` payload — the same type already flowing through `SentinelPipeline`. If no webhook is configured, `IAlertSink` is a no-op.

No new abstraction is needed beyond what `ZeroAlloc.Rest` provides.

---

## Architecture After Integration

```
Caller (Result-aware)          Caller (IChatClient)
        |                               |
   SentinelPipeline          SentinelChatClient (shim)
        |                               |
        +-------------------------------+
                       |
              DetectionPipeline
              (IDetector[] — source-generated registration)
                       |
              InterventionEngine
              (IMediator + IAlertSink)
                       |
                  IAuditStore
              (HeapRingBuffer<AuditEntry>)
```

---

## Out of Scope

- `ZeroAlloc.Cache` — deferred; unsafe for session-aware detectors
- Any changes to `IDetector` or `DetectionResult` — interfaces are stable
- Dashboard / streaming UI — separate initiative
