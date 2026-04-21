# Streaming Pipeline Support + Per-session Rate Limiting Design

**Goal:** Wire `GetStreamingResponseAsync` into the detection pipeline and add a per-session token-bucket circuit breaker against token-budget exhaustion.

**Architecture:** Streaming buffers the full inner response before yielding tokens to the caller — the security guarantee (no quarantined tokens ever reach application code) requires seeing the complete response before deciding. Rate limiting uses ZeroAlloc.Resilience's lock-free `RateLimiter` class per session key, gated at the top of `ScanAsync` before any detector work.

**Tech Stack:** ZeroAlloc.Resilience (lock-free token-bucket `RateLimiter`), `Microsoft.Extensions.AI` `ChatResponseUpdate`, BCL `ConcurrentDictionary`.

---

## Architecture

Four components, all additive — no existing public API is removed.

### 1. `SentinelPipeline.GetStreamingResultAsync`

New method parallel to `GetResponseResultAsync`. Performs the same two-pass scan but wraps a streaming inner client call.

### 2. `SentinelChatClient.StreamAsync` wired to sentinel

Currently a raw pass-through. After this change, delegates to `GetStreamingResultAsync` and yields from the returned buffer.

### 3. Rate limit gate in `SentinelPipeline`

Fires before the prompt scan on every call (`GetResponseResultAsync` and `GetStreamingResultAsync`). Uses a `ConcurrentDictionary<string, RateLimiter>` keyed by caller-supplied session key.

### 4. `SentinelError.RateLimitExceeded`

New error discriminated union case. Maps to `SentinelException` via the existing `ToException()` extension.

---

## Streaming Pipeline

### Behaviour

Every `GetStreamingResponseAsync` call buffers the complete inner stream before returning any token to the caller. This means:

- **Prompt blocked** (Quarantine): throws `SentinelException` — inner client is never called.
- **Response blocked** (Quarantine): throws `SentinelException` — buffer was collected but never yielded.
- **Alert / Log / PassThrough**: buffer flushed to caller after response scan completes.

**Known trade-off:** Streaming becomes batch delivery. Time-to-first-token equals total LLM response latency. True incremental delivery would require a post-scan append architecture; this is tracked in the backlog as a future enhancement.

### `SentinelPipeline.GetStreamingResultAsync`

```csharp
public async ValueTask<Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>>
    GetStreamingResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
{
    var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
    var sessionId = SessionId.New();

    // Rate limit check (shared helper with GetResponseResultAsync)
    var rateError = CheckRateLimit(chatOptions, sessionId);
    if (rateError is not null)
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(rateError);

    // Prompt scan
    var promptError = await ScanAsync(messageList, sessionId,
        options.DefaultSenderId, options.DefaultReceiverId, ct).ConfigureAwait(false);
    if (promptError is not null)
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(promptError);

    // Collect inner stream
    var buffer = new List<ChatResponseUpdate>();
    try
    {
        await foreach (var update in innerClient
            .GetStreamingResponseAsync(messageList, chatOptions, ct)
            .ConfigureAwait(false))
            buffer.Add(update);
    }
    catch (Exception ex)
    {
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(
            new SentinelError.PipelineFailure("Inner client streaming failed.", ex));
    }

    // Reconstruct response text for scanning
    var responseText = string.Concat(buffer.Select(u => u.Text ?? ""));
    IReadOnlyList<ChatMessage> responseMessages =
        [new ChatMessage(ChatRole.Assistant, responseText)];

    // Response scan
    var responseError = await ScanAsync(responseMessages, sessionId,
        options.DefaultReceiverId, options.DefaultSenderId, ct).ConfigureAwait(false);
    if (responseError is not null)
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(responseError);

    return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Success(buffer);
}
```

### `SentinelChatClient.StreamAsync`

```csharp
private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync(
    IEnumerable<ChatMessage> messages,
    ChatOptions? chatOptions,
    [EnumeratorCancellation] CancellationToken cancellationToken)
{
    var result = await _sentinel
        .GetStreamingResultAsync(messages, chatOptions, cancellationToken)
        .ConfigureAwait(false);
    foreach (var update in result.Match(ok => ok, err => throw err.ToException()))
        yield return update;
}
```

---

## Per-session Rate Limiting

### `SentinelOptions` additions

```csharp
/// <summary>Maximum LLM calls per second per session (token-bucket steady state).
/// Null (default) = no rate limiting. Pair with <see cref="BurstSize"/> to allow
/// initial spikes while capping sustained throughput.</summary>
public int? MaxCallsPerSecond { get; set; }

/// <summary>Burst capacity — initial and maximum token count for the rate limiter.
/// Defaults to <see cref="MaxCallsPerSecond"/> when null.
/// Set higher to absorb short spikes without throttling.</summary>
public int? BurstSize { get; set; }
```

### `SentinelPipeline` additions

```csharp
private static readonly Counter<long> _rateLimited =
    _meter.CreateCounter<long>("sentinel.rate_limit.exceeded");
private readonly ConcurrentDictionary<string, RateLimiter> _rateLimiters = new();
```

Rate check helper (called at the top of both `GetResponseResultAsync` and `GetStreamingResultAsync`):

```csharp
private SentinelError? CheckRateLimit(ChatOptions? chatOptions, SessionId sessionId)
{
    if (options.MaxCallsPerSecond is not int maxRps) return null;

    var sessionKey = chatOptions?.AdditionalProperties
        ?.GetValueOrDefault("sentinel.session_id") as string ?? "__global__";
    var burst = options.BurstSize ?? maxRps;
    var limiter = _rateLimiters.GetOrAdd(sessionKey,
        _ => new RateLimiter(maxRps, burst, RateLimitScope.Instance));

    if (limiter.TryAcquire()) return null;

    _rateLimited.Add(1, new TagList { ["session"] = sessionKey });
    return new SentinelError.RateLimitExceeded(sessionKey);
}
```

### Caller opt-in for per-session keys

Without a session key, all calls share the `"__global__"` bucket — still useful as a global pipeline circuit breaker.

```csharp
var opts = new ChatOptions();
(opts.AdditionalProperties ??= [])["sentinel.session_id"] = "user-42";
await chatClient.GetResponseAsync(messages, opts, ct);
```

### `SentinelError.RateLimitExceeded`

```csharp
public sealed record RateLimitExceeded(string SessionKey) : SentinelError;
```

`ToException()` maps this to `SentinelException` — same as `ThreatDetected`.

### DI / package

Add to `AI.Sentinel.csproj`:

```xml
<PackageReference Include="ZeroAlloc.Resilience" Version="1.*" />
```

No DI change needed — `_rateLimiters` and `_rateLimited` are fields on `SentinelPipeline`.

### Known limitation

`_rateLimiters` grows unbounded (one entry per unique session key). Tracked in backlog alongside `DeduplicatingAlertSink._seen`. Eviction can be added with `MemoryCache` or a background sweeper before v1.0.

---

## New metric

| Metric | Type | Description |
|---|---|---|
| `sentinel.rate_limit.exceeded` | Counter | Calls rejected by the rate limiter (tagged by `session`) |

---

## Testing

### `SentinelChatClientStreamingTests` (new)

| Test | Verifies |
|---|---|
| `CleanInput_YieldsAllUpdates` | All buffered tokens returned when both scans are clean |
| `ThreatInPrompt_ThrowsSentinelException` | Prompt scan blocks; inner client never called |
| `ThreatInResponse_ThrowsSentinelException` | Response scan blocks after full buffer collected |
| `AuditEntryWritten_ForStreamingCall` | Audit store written for the streaming path |

### `SentinelPipelineRateLimitTests` (new)

| Test | Verifies |
|---|---|
| `WithinBurst_Succeeds` | First `BurstSize` calls succeed |
| `ExceedsBurst_ReturnsRateLimitExceeded` | `BurstSize + 1`th call returns `RateLimitExceeded` |
| `Disabled_NoLimiting` | `MaxCallsPerSecond = null` imposes no restriction |
| `DifferentSessionKeys_IndependentBuckets` | Session A exhausted does not affect session B |
| `ExceedsLimit_EmitsMetric` | `sentinel.rate_limit.exceeded` counter incremented |

---

## Files changed

| Action | File |
|---|---|
| Modify | `src/AI.Sentinel/SentinelPipeline.cs` — `GetStreamingResultAsync`, `CheckRateLimit`, new fields |
| Modify | `src/AI.Sentinel/SentinelChatClient.cs` — wire `StreamAsync` → `GetStreamingResultAsync` |
| Modify | `src/AI.Sentinel/SentinelError.cs` — add `RateLimitExceeded` |
| Modify | `src/AI.Sentinel/SentinelOptions.cs` — `MaxCallsPerSecond`, `BurstSize` |
| Modify | `src/AI.Sentinel/AI.Sentinel.csproj` — add `ZeroAlloc.Resilience 1.*` |
| New | `tests/AI.Sentinel.Tests/SentinelChatClientStreamingTests.cs` |
| New | `tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs` |
| Modify | `README.md` — streaming behaviour note, rate limiting config + metric |
| Modify | `docs/BACKLOG.md` — remove implemented items, add `_rateLimiters` eviction |
