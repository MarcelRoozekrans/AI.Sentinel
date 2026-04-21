# Streaming Pipeline Support + Per-session Rate Limiting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Scan `GetStreamingResponseAsync` calls through the full detection pipeline, and add a per-session token-bucket circuit breaker using `ZeroAlloc.Resilience.RateLimiter`.

**Architecture:** Streaming buffers the entire inner response before yielding tokens so the response scan can quarantine before any token reaches the caller. Rate limiting uses a `ConcurrentDictionary<string, RateLimiter>` keyed by an optional caller-supplied `"sentinel.session_id"` in `ChatOptions.AdditionalProperties`; without a key, all calls share a `"__global__"` bucket.

**Tech Stack:** ZeroAlloc.Resilience 1.0.* (lock-free token-bucket `RateLimiter`), `Microsoft.Extensions.AI` (`ChatResponseUpdate`, `IAsyncEnumerable`), ZeroAlloc.Results, xUnit.

---

## Context: Key files

- `src/AI.Sentinel/SentinelPipeline.cs` — two-pass scan + intervention logic; the `ScanAsync` private helper is reused as-is
- `src/AI.Sentinel/SentinelChatClient.cs` — `DelegatingChatClient` wrapper; `StreamAsync` is currently a raw pass-through with no scanning
- `src/AI.Sentinel/SentinelError.cs` — discriminated union; `ToException()` switch must handle the new case
- `src/AI.Sentinel/SentinelOptions.cs` — config; new properties go here
- `src/AI.Sentinel/AI.Sentinel.csproj` — `net8.0;net9.0` targets; add `ZeroAlloc.Resilience 1.0.*` here
- `tests/AI.Sentinel.Tests/SentinelChatClientTests.cs` — has one test that pins old "streaming is a pass-through" contract; update it in Task 4
- `tests/AI.Sentinel.Tests/SentinelErrorTests.cs` — add test for new error case in Task 1
- `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs` — add test for new properties in Task 2

**Test runner command:**
```bash
dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --no-build -v m 2>&1 | tail -20
```
Build command (run to check compilation):
```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -20
```

---

## Task 1: Add `ZeroAlloc.Resilience` package + `RateLimitExceeded` error case

**Files:**
- Modify: `src/AI.Sentinel/AI.Sentinel.csproj`
- Modify: `src/AI.Sentinel/SentinelError.cs`
- Modify: `tests/AI.Sentinel.Tests/SentinelErrorTests.cs`

**Step 1: Write the failing test**

Add to `tests/AI.Sentinel.Tests/SentinelErrorTests.cs` (inside the `SentinelErrorTests` class, after the existing tests):

```csharp
[Fact]
public void RateLimitExceeded_ToException_ReturnsSentinelException()
{
    var error = new SentinelError.RateLimitExceeded("user-42");
    var ex = error.ToException();
    var sentinelEx = Assert.IsType<SentinelException>(ex);
    Assert.Contains("user-42", sentinelEx.Message, StringComparison.Ordinal);
}
```

**Step 2: Run test to verify it fails**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "RateLimitExceeded_ToException" 2>&1 | tail -10
```

Expected: build error — `SentinelError.RateLimitExceeded` does not exist.

**Step 3: Add the NuGet package**

In `src/AI.Sentinel/AI.Sentinel.csproj`, add inside the existing `<ItemGroup>` with other `PackageReference` entries:

```xml
<PackageReference Include="ZeroAlloc.Resilience" Version="1.0.*" />
```

**Step 4: Add `RateLimitExceeded` to `SentinelError`**

In `src/AI.Sentinel/SentinelError.cs`, add the new record type after the existing `PipelineFailure` record (line 19):

```csharp
/// <summary>Indicates the per-session rate limit was exceeded.</summary>
/// <param name="SessionKey">The session key that exceeded its call budget.</param>
public sealed record RateLimitExceeded(string SessionKey) : SentinelError;
```

And update the `ToException()` switch expression — change the `_ =>` fallthrough line to add the new case before it:

```csharp
RateLimitExceeded r => new SentinelException(
    $"AI.Sentinel rate limit exceeded for session '{r.SessionKey}'."),
_ => new InvalidOperationException("Unknown SentinelError")
```

**Step 5: Run test to verify it passes**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "RateLimitExceeded_ToException" 2>&1 | tail -10
```

Expected: PASS.

**Step 6: Run full test suite**

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: all existing tests still pass.

**Step 7: Commit**

```bash
git add src/AI.Sentinel/AI.Sentinel.csproj src/AI.Sentinel/SentinelError.cs tests/AI.Sentinel.Tests/SentinelErrorTests.cs
git commit -m "feat: add RateLimitExceeded error case and ZeroAlloc.Resilience package"
```

---

## Task 2: Add `MaxCallsPerSecond` and `BurstSize` to `SentinelOptions`

**Files:**
- Modify: `src/AI.Sentinel/SentinelOptions.cs`
- Modify: `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs`

**Step 1: Write the failing test**

Add to `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs` (inside the `SentinelOptionsTests` class):

```csharp
[Fact]
public void MaxCallsPerSecond_And_BurstSize_DefaultToNull()
{
    var opts = new SentinelOptions();
    Assert.Null(opts.MaxCallsPerSecond);
    Assert.Null(opts.BurstSize);
}
```

**Step 2: Run test to verify it fails**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "MaxCallsPerSecond_And_BurstSize" 2>&1 | tail -10
```

Expected: build error — properties do not exist.

**Step 3: Add properties to `SentinelOptions`**

In `src/AI.Sentinel/SentinelOptions.cs`, add after the `AlertDeduplicationWindow` property (line 33):

```csharp
/// <summary>Maximum LLM calls per second per session (token-bucket steady state).
/// Null (default) = no rate limiting. Pair with <see cref="BurstSize"/> to allow
/// initial spikes while capping sustained throughput.
/// Uses <c>ZeroAlloc.Resilience.RateLimiter</c> — one bucket per session key.</summary>
public int? MaxCallsPerSecond { get; set; }

/// <summary>Burst capacity — initial and maximum token count for the per-session rate limiter.
/// Defaults to <see cref="MaxCallsPerSecond"/> when null.
/// Set higher than <see cref="MaxCallsPerSecond"/> to absorb short spikes without throttling.</summary>
public int? BurstSize { get; set; }
```

**Step 4: Run test to verify it passes**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "MaxCallsPerSecond_And_BurstSize" 2>&1 | tail -10
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/AI.Sentinel/SentinelOptions.cs tests/AI.Sentinel.Tests/SentinelOptionsTests.cs
git commit -m "feat: add MaxCallsPerSecond and BurstSize to SentinelOptions"
```

---

## Task 3: Implement per-session rate limiting in `SentinelPipeline`

Rate limiting fires at the top of `GetResponseResultAsync`, before any scan work. The `CheckRateLimit` private helper will also be reused by `GetStreamingResultAsync` in Task 4.

**Files:**
- Create: `tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs`
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`

**Step 1: Write the failing tests**

Create `tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs`:

```csharp
using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelPipelineRateLimitTests
{
    private static SentinelPipeline Build(int? maxCallsPerSecond, int? burstSize = null)
    {
        var opts = new SentinelOptions { MaxCallsPerSecond = maxCallsPerSecond, BurstSize = burstSize };
        var pipeline = new DetectionPipeline([], null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        return new SentinelPipeline(new NoOpChatClient(), pipeline, audit, engine, opts);
    }

    [Fact]
    public async Task WithinBurst_Succeeds()
    {
        var sentinel = Build(maxCallsPerSecond: 10, burstSize: 3);
        for (var i = 0; i < 3; i++)
        {
            var result = await sentinel.GetResponseResultAsync(
                [new ChatMessage(ChatRole.User, "hi")], null, default);
            Assert.True(result.IsSuccess);
        }
    }

    [Fact]
    public async Task ExceedsBurst_ReturnsRateLimitExceeded()
    {
        var sentinel = Build(maxCallsPerSecond: 100, burstSize: 2);
        await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, default);
        await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, default);

        var result = await sentinel.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "hi")], null, default);
        Assert.True(result.IsFailure);
        Assert.IsType<SentinelError.RateLimitExceeded>(result.Error);
    }

    [Fact]
    public async Task Disabled_NoLimiting()
    {
        var sentinel = Build(maxCallsPerSecond: null);
        for (var i = 0; i < 50; i++)
        {
            var result = await sentinel.GetResponseResultAsync(
                [new ChatMessage(ChatRole.User, "hi")], null, default);
            Assert.True(result.IsSuccess);
        }
    }

    [Fact]
    public async Task DifferentSessionKeys_IndependentBuckets()
    {
        var sentinel = Build(maxCallsPerSecond: 100, burstSize: 1);
        var opts1 = new ChatOptions();
        opts1.AdditionalProperties = new AdditionalPropertiesDictionary
        {
            ["sentinel.session_id"] = "session-A"
        };
        var opts2 = new ChatOptions();
        opts2.AdditionalProperties = new AdditionalPropertiesDictionary
        {
            ["sentinel.session_id"] = "session-B"
        };

        // Exhaust session-A bucket (burst = 1)
        await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts1, default);
        var resultA = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts1, default);
        Assert.IsType<SentinelError.RateLimitExceeded>(resultA.Error);

        // Session-B is independent — should succeed
        var resultB = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts2, default);
        Assert.True(resultB.IsSuccess);
    }

    private sealed class NoOpChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages,
            ChatOptions? options = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "ok")]));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => throw new NotSupportedException();

        public ChatClientMetadata Metadata => new("test", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
```

**Step 2: Run tests to verify they fail**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "SentinelPipelineRateLimitTests" 2>&1 | tail -15
```

Expected: build succeeds, all 4 tests fail — `CheckRateLimit` / `_rateLimiters` do not exist yet.

**Step 3: Add rate limiting to `SentinelPipeline`**

In `src/AI.Sentinel/SentinelPipeline.cs`, add the `ZeroAlloc.Resilience` using at the top:

```csharp
using ZeroAlloc.Resilience;
```

Add two new static/instance fields after the existing `_activitySource` field (around line 26):

```csharp
private static readonly Counter<long> _rateLimited =
    _meter.CreateCounter<long>("sentinel.rate_limit.exceeded");
private readonly ConcurrentDictionary<string, RateLimiter> _rateLimiters = new();
```

Add the `CheckRateLimit` private method after the `ScanAsync` method (just before `AppendAuditAsync`):

```csharp
private SentinelError? CheckRateLimit(ChatOptions? chatOptions)
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

At the top of `GetResponseResultAsync`, before the existing `var messageList = ...` line, add:

```csharp
var rateError = CheckRateLimit(chatOptions);
if (rateError is not null)
    return Result<ChatResponse, SentinelError>.Failure(rateError);
```

**Step 4: Build to check compilation**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -10
```

Expected: 0 errors.

**Step 5: Run rate limit tests to verify they pass**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "SentinelPipelineRateLimitTests" 2>&1 | tail -15
```

Expected: all 4 tests PASS.

**Step 6: Run full test suite**

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: all tests pass.

**Step 7: Commit**

```bash
git add src/AI.Sentinel/SentinelPipeline.cs tests/AI.Sentinel.Tests/SentinelPipelineRateLimitTests.cs
git commit -m "feat: add per-session rate limiting to SentinelPipeline"
```

---

## Task 4: Add streaming pipeline support

**This task adds:**
1. `SentinelPipeline.GetStreamingResultAsync` — buffers the full inner stream, scans prompt + response, returns the buffer or an error
2. Wires `SentinelChatClient.StreamAsync` to call it
3. Updates the existing test that pinned the old "no-scan" streaming contract

**Files:**
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`
- Modify: `src/AI.Sentinel/SentinelChatClient.cs`
- Create: `tests/AI.Sentinel.Tests/SentinelChatClientStreamingTests.cs`
- Modify: `tests/AI.Sentinel.Tests/SentinelChatClientTests.cs` — update one test

**Step 1: Write the failing streaming tests**

Create `tests/AI.Sentinel.Tests/SentinelChatClientStreamingTests.cs`:

```csharp
using System.Runtime.CompilerServices;
using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;

namespace AI.Sentinel.Tests;

public class SentinelChatClientStreamingTests
{
    private static IChatClient BuildClient(
        IChatClient inner,
        SentinelOptions? opts = null,
        IDetector[]? detectors = null)
    {
        var options = opts ?? new SentinelOptions();
        var pipeline = new DetectionPipeline(detectors ?? [], null);
        var store = new RingBufferAuditStore();
        var engine = new InterventionEngine(options, mediator: null);
        return new SentinelChatClient(inner, pipeline, store, engine, options);
    }

    [Fact]
    public async Task CleanInput_YieldsAllUpdates()
    {
        var inner = new StreamingFakeClient("hello", " world");
        var client = BuildClient(inner);

        var chunks = new List<ChatResponseUpdate>();
        await foreach (var update in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")]))
            chunks.Add(update);

        Assert.Equal(2, chunks.Count);
        Assert.Equal("hello world", string.Concat(chunks.Select(c => c.Text ?? "")));
    }

    [Fact]
    public async Task ThreatInPrompt_ThrowsSentinelException()
    {
        // Prompt scan fires before inner client is called
        var inner = new StreamingFakeClient("response");
        var client = BuildClient(inner,
            opts: new SentinelOptions { OnCritical = SentinelAction.Quarantine },
            detectors: [new AlwaysCriticalDetector()]);

        await Assert.ThrowsAsync<SentinelException>(async () =>
        {
            await foreach (var _ in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "hostile")]))
            { }
        });
    }

    [Fact]
    public async Task ThreatInResponse_ThrowsSentinelException()
    {
        // Inner client returns a message that the response-only detector flags
        var inner = new StreamingFakeClient("malicious reply");
        var client = BuildClient(inner,
            opts: new SentinelOptions { OnCritical = SentinelAction.Quarantine },
            detectors: [new ResponseOnlyDetector()]);

        await Assert.ThrowsAsync<SentinelException>(async () =>
        {
            await foreach (var _ in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "clean prompt")]))
            { }
        });
    }

    [Fact]
    public async Task AuditEntry_WrittenForStreamingCall()
    {
        var inner = new StreamingFakeClient("ok");
        var store = new RingBufferAuditStore(100);
        var opts = new SentinelOptions();
        var pipeline = new DetectionPipeline([new AlwaysCriticalDetector()], null);
        var engine = new InterventionEngine(opts, null);
        // Use Alert so we get an audit entry without throwing
        opts.OnCritical = SentinelAction.Alert;
        var client = new SentinelChatClient(new StreamingFakeClient("ok"), pipeline, store, engine, opts);

        await foreach (var _ in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")]))
        { }

        var entries = new List<AuditEntry>();
        await foreach (var entry in store.QueryAsync(new AuditQuery(), default))
            entries.Add(entry);
        Assert.NotEmpty(entries);
    }

    // ---- Detectors ----

    private sealed class AlwaysCriticalDetector : IDetector
    {
        public DetectorId Id => new("TST-99");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "fake threat"));
    }

    private sealed class ResponseOnlyDetector : IDetector
    {
        public DetectorId Id => new("RESP-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            var hasAssistantMessage = ctx.Messages.Any(m => m.Role == ChatRole.Assistant);
            return hasAssistantMessage
                ? ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "response threat"))
                : ValueTask.FromResult(DetectionResult.Clean(Id));
        }
    }

    // ---- Test double ----

    private sealed class StreamingFakeClient(params string[] chunks) : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages,
            ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(
                [new ChatMessage(ChatRole.Assistant, string.Concat(chunks))]));

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            foreach (var chunk in chunks)
            {
                await Task.Yield();
                yield return new ChatResponseUpdate(ChatRole.Assistant, chunk);
            }
        }

        public ChatClientMetadata Metadata => new("test", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
```

**Step 2: Run tests to verify they fail**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "SentinelChatClientStreamingTests" 2>&1 | tail -15
```

Expected: `CleanInput_YieldsAllUpdates` might pass (streaming still a pass-through), but `ThreatInPrompt_ThrowsSentinelException` and `ThreatInResponse_ThrowsSentinelException` fail — the current streaming path doesn't scan.

**Step 3: Add `GetStreamingResultAsync` to `SentinelPipeline`**

In `src/AI.Sentinel/SentinelPipeline.cs`, add this method after `GetResponseResultAsync` (after the closing `}` of that method, before `private async ValueTask<SentinelError?> ScanAsync`):

```csharp
/// <summary>Buffers the full inner streaming response, scans both prompt and response,
/// and returns the buffer on success or a <see cref="SentinelError"/> on failure.</summary>
/// <remarks>
/// Buffering is intentional — it ensures a quarantined response never reaches the caller.
/// Time-to-first-token equals total LLM response latency on this path.
/// </remarks>
public async ValueTask<Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>> GetStreamingResultAsync(
    IEnumerable<ChatMessage> messages,
    ChatOptions? chatOptions,
    CancellationToken ct)
{
    var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
    var sessionId = SessionId.New();

    var rateError = CheckRateLimit(chatOptions);
    if (rateError is not null)
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(rateError);

    var promptError = await ScanAsync(messageList, sessionId,
        options.DefaultSenderId, options.DefaultReceiverId, ct).ConfigureAwait(false);
    if (promptError is not null)
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(promptError);

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

    var responseText = string.Concat(buffer.Select(u => u.Text ?? ""));
    IReadOnlyList<ChatMessage> responseMessages =
        [new ChatMessage(ChatRole.Assistant, responseText)];

    var responseError = await ScanAsync(responseMessages, sessionId,
        options.DefaultReceiverId, options.DefaultSenderId, ct).ConfigureAwait(false);
    if (responseError is not null)
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(responseError);

    return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Success(buffer);
}
```

**Step 4: Wire `SentinelChatClient.StreamAsync`**

In `src/AI.Sentinel/SentinelChatClient.cs`, replace the body of `StreamAsync` (lines 39–46):

Remove (the entire method body):
```csharp
    // Streaming is a pass-through with no sentinel scan — scanning streamed responses
    // requires SentinelPipeline.GetStreamingResultAsync, which is a future backlog item.
    private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var update in base.GetStreamingResponseAsync(messages, chatOptions, cancellationToken)
            .ConfigureAwait(false))
            yield return update;
    }
```

Replace with:
```csharp
    private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var result = await _sentinel
            .GetStreamingResultAsync(messages, chatOptions, cancellationToken)
            .ConfigureAwait(false);
        if (result.IsFailure)
            throw result.Error.ToException();
        foreach (var update in result.Value)
            yield return update;
    }
```

**Step 5: Update the existing test that pins old "pass-through" contract**

In `tests/AI.Sentinel.Tests/SentinelChatClientTests.cs`, find the test `GetStreamingResponseAsync_WithCriticalDetector_PassesThroughWithoutException` (lines 55–74) and replace it entirely:

```csharp
[Fact]
public async Task GetStreamingResponseAsync_WithCriticalDetector_ThrowsSentinelException()
{
    // Streaming now runs the full detection pipeline — a Critical threat must block.
    var inner = new StreamingFakeChatClient("streamed chunk");
    var client = BuildSentinelClient(inner,
        opts: new SentinelOptions { OnCritical = SentinelAction.Quarantine },
        detectors: [new FakeCriticalDetector()]);

    await Assert.ThrowsAsync<SentinelException>(async () =>
    {
        await foreach (var _ in client.GetStreamingResponseAsync(
            new List<ChatMessage> { new(ChatRole.User, "hostile input") }))
        { }
    });
}
```

**Step 6: Build to check compilation**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -10
```

Expected: 0 errors.

**Step 7: Run streaming tests to verify they pass**

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "SentinelChatClientStreamingTests|SentinelChatClientTests" 2>&1 | tail -20
```

Expected: all tests PASS (including the renamed test in `SentinelChatClientTests`).

**Step 8: Run full test suite**

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: all tests pass.

**Step 9: Commit**

```bash
git add src/AI.Sentinel/SentinelPipeline.cs src/AI.Sentinel/SentinelChatClient.cs tests/AI.Sentinel.Tests/SentinelChatClientStreamingTests.cs tests/AI.Sentinel.Tests/SentinelChatClientTests.cs
git commit -m "feat: add streaming pipeline support with full detection scan"
```

---

## Task 5: Update README and BACKLOG

**Files:**
- Modify: `README.md`
- Modify: `docs/BACKLOG.md`

**Step 1: Update `README.md`**

**In the Configuration section** — add the two new options after `AlertDeduplicationWindow`:

```csharp
    // Optional: per-session token-bucket circuit breaker.
    // MaxCallsPerSecond = steady-state refill rate; BurstSize = initial token count.
    // Pass "sentinel.session_id" in ChatOptions.AdditionalProperties for per-user buckets.
    // Without a session key, all calls share a global bucket.
    opts.MaxCallsPerSecond = 5;   // allow 5 calls/sec per session (steady state)
    opts.BurstSize = 20;          // up-front burst before throttling kicks in
```

**In the OpenTelemetry → Metrics table** — add the new metric row:

```
| `sentinel.rate_limit.exceeded` | Counter | Calls rejected by the per-session rate limiter (tagged by `session`) |
```

**In the Packages / How it works section** — add a note after the table that streaming is now fully scanned:

Find the line:
```
> **LLM escalation detectors** are no-ops until `opts.EscalationClient` is configured.
```

Before it, add:
```
> **Streaming**: `GetStreamingResponseAsync` buffers the complete response before yielding tokens so the response scan can quarantine before any token reaches the application. Time-to-first-token equals full model response latency on this path.
```

**Step 2: Update `docs/BACKLOG.md`**

Remove the item **Streaming pipeline support** from the Architecture / Integration section (it is now implemented).

Remove the item **Per-session rate limiting** from the Architecture / Integration section (it is now implemented).

Add a new row to the Architecture / Integration section:

```
| **Add eviction to `SentinelPipeline._rateLimiters`** | The `ConcurrentDictionary<string, RateLimiter>` grows unbounded — one entry per unique session key for the pipeline lifetime. Add a background sweeper or `MemoryCache` with sliding expiry. Same category as `DeduplicatingAlertSink._seen`. |
```

**Step 3: Run the full test suite one final time**

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: all tests pass.

**Step 4: Commit**

```bash
git add README.md docs/BACKLOG.md
git commit -m "docs: update README and BACKLOG for streaming + rate limiting"
```
