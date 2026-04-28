# Persistent Audit Store + External Forwarders Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship two related capabilities for enterprise audit: a persistent `SqliteAuditStore` (replaces the in-memory ring buffer) and an `IAuditForwarder` abstraction with three reference impls (NDJSON file, Azure Sentinel, OpenTelemetry) that mirror every audit entry to external SIEM/observability systems.

**Architecture:** Two separate concerns with separate DI registrations. `IAuditStore` is singular (source of truth, awaited). `IEnumerable<IAuditForwarder>` is plural (best-effort, fire-and-forget). Pipeline writes to store first, then loops through forwarders. `BufferingAuditForwarder<T>` decorator handles batching for forwarders that need it (Azure Sentinel); NDJSON skips it (direct file append is already fast); OTel skips it (SDK batches itself).

**Tech Stack:** .NET 9, `Microsoft.Data.Sqlite`, `Azure.Monitor.Ingestion`, `OpenTelemetry.Logs`, xUnit. Three new packages; `IAuditForwarder` + buffering decorator + NDJSON forwarder live in core.

**Reference:** [docs/plans/2026-04-28-persistent-audit-and-forwarders-design.md](2026-04-28-persistent-audit-and-forwarders-design.md) — full design rationale.

---

## Task 1: `IAuditForwarder` + `BufferingAuditForwarder<T>` (core abstractions)

**Files:**
- Create: `src/AI.Sentinel/Audit/IAuditForwarder.cs`
- Create: `src/AI.Sentinel/Audit/BufferingAuditForwarder.cs`
- Create: `src/AI.Sentinel/Audit/BufferingAuditForwarderOptions.cs`
- Create: `tests/AI.Sentinel.Tests/Audit/BufferingAuditForwarderTests.cs`

### Step 0: Read existing audit infrastructure

- `src/AI.Sentinel/Audit/IAuditStore.cs` — see existing interface shape, `[Instrument]` annotations
- `src/AI.Sentinel/Audit/AuditEntry.cs` — confirm record shape (used in `IReadOnlyList<AuditEntry>` parameter)
- `src/AI.Sentinel/Alerts/IAlertSink.cs` — pattern reference (similar fire-and-forget + telemetry posture)
- `src/AI.Sentinel.Mcp/Logging/StderrLogger.cs` — used for overflow logging

### Step 1: Write the failing tests

```csharp
// tests/AI.Sentinel.Tests/Audit/BufferingAuditForwarderTests.cs
using System.Threading.Channels;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class BufferingAuditForwarderTests
{
    private static AuditEntry MakeEntry(string id = "e1") =>
        new() { Id = id, Timestamp = DateTimeOffset.UtcNow,
                Hash = "h", PreviousHash = null,
                Severity = Severity.Low, DetectorId = "T-01", Summary = "test" };

    [Fact]
    public async Task SizeThreshold_FlushesBatch()
    {
        var inner = new RecordingForwarder();
        await using var buf = new BufferingAuditForwarder<RecordingForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 3, MaxFlushInterval = TimeSpan.FromSeconds(60) });

        for (var i = 0; i < 3; i++)
            await buf.SendAsync([MakeEntry($"e{i}")], default);

        // Wait briefly for the background reader
        await Task.Delay(200);

        Assert.Single(inner.Batches);
        Assert.Equal(3, inner.Batches[0].Count);
    }

    [Fact]
    public async Task IntervalThreshold_FlushesBatch()
    {
        var inner = new RecordingForwarder();
        await using var buf = new BufferingAuditForwarder<RecordingForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1000, MaxFlushInterval = TimeSpan.FromMilliseconds(150) });

        await buf.SendAsync([MakeEntry()], default);
        await Task.Delay(400);

        Assert.Single(inner.Batches);
        Assert.Single(inner.Batches[0]);
    }

    [Fact]
    public async Task ChannelOverflow_DropsAndIncrementsCounter()
    {
        var inner = new BlockingForwarder(); // never completes — channel fills up
        await using var buf = new BufferingAuditForwarder<BlockingForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1, ChannelCapacity = 2,
                                                  MaxFlushInterval = TimeSpan.FromSeconds(60) });

        // Push enough to overflow (2 capacity + 1 reader holding + extras)
        for (var i = 0; i < 20; i++)
            await buf.SendAsync([MakeEntry($"e{i}")], default);

        Assert.True(buf.DroppedCount > 0, "Expected drops once channel filled");
    }

    [Fact]
    public async Task DisposeAsync_FlushesPendingBatch()
    {
        var inner = new RecordingForwarder();
        var buf = new BufferingAuditForwarder<RecordingForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1000, MaxFlushInterval = TimeSpan.FromSeconds(60) });

        await buf.SendAsync([MakeEntry()], default);
        await buf.DisposeAsync();

        Assert.Single(inner.Batches);
    }

    [Fact]
    public async Task InnerThrows_ExceptionSwallowed_KeepsRunning()
    {
        var inner = new ThrowOnceForwarder();
        await using var buf = new BufferingAuditForwarder<ThrowOnceForwarder>(inner,
            new BufferingAuditForwarderOptions { MaxBatchSize = 1, MaxFlushInterval = TimeSpan.FromMilliseconds(50) });

        await buf.SendAsync([MakeEntry("e1")], default); // first batch — inner throws
        await Task.Delay(150);
        await buf.SendAsync([MakeEntry("e2")], default); // second — must still ship
        await Task.Delay(150);

        Assert.Equal(1, inner.SuccessfulSends);
    }

    private sealed class RecordingForwarder : IAuditForwarder
    {
        public List<IReadOnlyList<AuditEntry>> Batches { get; } = new();
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            Batches.Add(batch);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class BlockingForwarder : IAuditForwarder
    {
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
            => new(Task.Delay(Timeout.Infinite, ct));
    }

    private sealed class ThrowOnceForwarder : IAuditForwarder
    {
        private int _calls;
        public int SuccessfulSends { get; private set; }
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _calls) == 1)
                throw new InvalidOperationException("first call boom");
            SuccessfulSends++;
            return ValueTask.CompletedTask;
        }
    }
}
```

### Step 2: Run tests to confirm they fail

```
dotnet test tests/AI.Sentinel.Tests --filter "BufferingAuditForwarderTests"
```
Expected: fail — types not found.

### Step 3: Implement `IAuditForwarder`

```csharp
// src/AI.Sentinel/Audit/IAuditForwarder.cs
using ZeroAlloc.Telemetry;

namespace AI.Sentinel.Audit;

/// <summary>Ships audit entries to an external system (SIEM, log aggregator, etc.). Implementations MUST NOT throw — failures are swallowed and surfaced via stderr / metrics.</summary>
[Instrument("ai.sentinel")]
public interface IAuditForwarder
{
    /// <summary>Sends a batch of audit entries. Single-entry lists are valid for forwarders without buffering.</summary>
    [Trace("audit.forward.send")]
    [Count("audit.forward.batches")]
    [Histogram("audit.forward.duration_ms")]
    ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct);
}
```

### Step 4: Implement `BufferingAuditForwarderOptions`

```csharp
// src/AI.Sentinel/Audit/BufferingAuditForwarderOptions.cs
namespace AI.Sentinel.Audit;

/// <summary>Configuration for <see cref="BufferingAuditForwarder{TInner}"/>.</summary>
public sealed class BufferingAuditForwarderOptions
{
    /// <summary>Maximum entries per batch before forced flush. Default 100.</summary>
    public int MaxBatchSize { get; set; } = 100;

    /// <summary>Maximum time between flushes regardless of batch size. Default 5 seconds.</summary>
    public TimeSpan MaxFlushInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Maximum entries buffered before drops occur. Default 10 000.</summary>
    public int ChannelCapacity { get; set; } = 10_000;
}
```

### Step 5: Implement `BufferingAuditForwarder<TInner>`

```csharp
// src/AI.Sentinel/Audit/BufferingAuditForwarder.cs
using System.Threading.Channels;
using AI.Sentinel.Mcp.Logging;

namespace AI.Sentinel.Audit;

/// <summary>Decorates an <see cref="IAuditForwarder"/> with channel-backed batching. Drops on overflow + increments <see cref="DroppedCount"/>; rate-limits stderr log of drops to once per second.</summary>
public sealed class BufferingAuditForwarder<TInner> : IAuditForwarder, IAsyncDisposable
    where TInner : IAuditForwarder
{
    private readonly TInner _inner;
    private readonly BufferingAuditForwarderOptions _options;
    private readonly Channel<AuditEntry> _channel;
    private readonly Task _readerTask;
    private readonly CancellationTokenSource _cts = new();
    private long _droppedCount;
    private long _lastDropLogTicks;

    public long DroppedCount => Interlocked.Read(ref _droppedCount);

    public BufferingAuditForwarder(TInner inner, BufferingAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(options);
        _inner = inner;
        _options = options;
        _channel = Channel.CreateBounded<AuditEntry>(new BoundedChannelOptions(options.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = false,
        });
        _readerTask = Task.Run(() => ReadLoopAsync(_cts.Token));
    }

    public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        foreach (var entry in batch)
        {
            if (!_channel.Writer.TryWrite(entry))
                OnDrop();
        }
        return ValueTask.CompletedTask;
    }

    private void OnDrop()
    {
        Interlocked.Increment(ref _droppedCount);

        // Rate-limit stderr to once per second to avoid log floods on outage
        var nowTicks = DateTime.UtcNow.Ticks;
        var lastTicks = Interlocked.Read(ref _lastDropLogTicks);
        if (nowTicks - lastTicks > TimeSpan.TicksPerSecond
            && Interlocked.CompareExchange(ref _lastDropLogTicks, nowTicks, lastTicks) == lastTicks)
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"]   = "audit_forward",
                ["action"]  = "drop",
                ["dropped"] = Interlocked.Read(ref _droppedCount).ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["forwarder"] = typeof(TInner).Name,
            });
        }
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var batch = new List<AuditEntry>(_options.MaxBatchSize);
        var lastFlush = DateTime.UtcNow;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var elapsed = DateTime.UtcNow - lastFlush;
                var remaining = _options.MaxFlushInterval - elapsed;
                if (remaining > TimeSpan.Zero)
                    timeoutCts.CancelAfter(remaining);

                AuditEntry entry;
                try
                {
                    entry = await _channel.Reader.ReadAsync(timeoutCts.Token).ConfigureAwait(false);
                    batch.Add(entry);
                }
                catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
                {
                    // interval timeout — flush whatever we have
                }

                if (batch.Count >= _options.MaxBatchSize ||
                    (batch.Count > 0 && DateTime.UtcNow - lastFlush >= _options.MaxFlushInterval))
                {
                    await FlushAsync(batch, ct).ConfigureAwait(false);
                    batch = new List<AuditEntry>(_options.MaxBatchSize);
                    lastFlush = DateTime.UtcNow;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["event"] = "audit_forward",
                    ["action"] = "reader_error",
                    ["error"] = ex.GetType().Name,
                });
            }
        }

        // Final flush on shutdown
        if (batch.Count > 0)
            await FlushAsync(batch, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task FlushAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        try
        {
            await _inner.SendAsync(batch, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"]    = "audit_forward",
                ["action"]   = "flush_error",
                ["forwarder"] = typeof(TInner).Name,
                ["error"]    = ex.GetType().Name,
            });
        }
    }

    public async ValueTask DisposeAsync()
    {
        _channel.Writer.Complete();
        try
        {
            await _readerTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (TimeoutException) { /* reader stuck — give up */ }
        _cts.Cancel();
        _cts.Dispose();
    }
}
```

### Step 6: Run tests

```
dotnet test tests/AI.Sentinel.Tests --filter "BufferingAuditForwarderTests"
```
Expected: 5 pass.

### Step 7: Run full suite

```
dotnet test tests/AI.Sentinel.Tests
```
Expected: existing 466 + 5 new = 471 pass.

### Step 8: Commit

```bash
git add src/AI.Sentinel/Audit/IAuditForwarder.cs \
        src/AI.Sentinel/Audit/BufferingAuditForwarder.cs \
        src/AI.Sentinel/Audit/BufferingAuditForwarderOptions.cs \
        tests/AI.Sentinel.Tests/Audit/BufferingAuditForwarderTests.cs
git commit -m "feat(audit): IAuditForwarder + BufferingAuditForwarder<T> decorator"
```

The commit IS authorized as part of the task spec.

---

## Task 2: `SentinelPipeline` integration — forwarder loop

**Files:**
- Modify: `src/AI.Sentinel/SentinelPipeline.cs` — add optional `IEnumerable<IAuditForwarder>?` ctor parameter; loop fire-and-forget after audit append
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs` — pass `IEnumerable<IAuditForwarder>` from DI to the pipeline ctor
- Create: `tests/AI.Sentinel.Tests/Audit/PipelineForwarderIntegrationTests.cs`

### Step 0: Read the current pipeline shape

- `src/AI.Sentinel/SentinelPipeline.cs` — find the existing audit-append site (somewhere it calls `_audit.AppendAsync(entry, ct)`). Note the existing ctor signature.
- `src/AI.Sentinel/ServiceCollectionExtensions.cs` — find the `SentinelPipeline` registration; note how `IAuditStore` is currently resolved.

### Step 1: Write failing tests

```csharp
// tests/AI.Sentinel.Tests/Audit/PipelineForwarderIntegrationTests.cs
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class PipelineForwarderIntegrationTests
{
    [Fact]
    public async Task AuditAppend_InvokesForwarderWithSingleEntryBatch()
    {
        var fwd = new RecordingForwarder();
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.OnHigh = SentinelAction.Log);
        services.AddSingleton<IAuditForwarder>(fwd);
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);

        // Wait for fire-and-forget propagation
        await Task.Delay(100);

        Assert.NotEmpty(fwd.Batches);
        Assert.All(fwd.Batches, b => Assert.Single(b)); // single-entry batches
    }

    [Fact]
    public async Task MultipleForwarders_AllReceiveEntry()
    {
        var fwdA = new RecordingForwarder();
        var fwdB = new RecordingForwarder();
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddSingleton<IAuditForwarder>(fwdA);
        services.AddSingleton<IAuditForwarder>(fwdB);
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);
        await Task.Delay(100);

        Assert.NotEmpty(fwdA.Batches);
        Assert.NotEmpty(fwdB.Batches);
    }

    [Fact]
    public async Task NoForwardersRegistered_PipelineWorksUnchanged()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        var response = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task SlowForwarder_DoesNotBlockPipeline()
    {
        var slow = new SlowForwarder(TimeSpan.FromSeconds(2));
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddSingleton<IAuditForwarder>(slow);
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);
        sw.Stop();

        Assert.True(sw.Elapsed < TimeSpan.FromMilliseconds(500), $"Pipeline should NOT block on slow forwarder; elapsed={sw.Elapsed}");
    }

    private sealed class RecordingForwarder : IAuditForwarder
    {
        public List<IReadOnlyList<AuditEntry>> Batches { get; } = new();
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            lock (Batches) Batches.Add(batch);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class SlowForwarder(TimeSpan delay) : IAuditForwarder
    {
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
            => new(Task.Delay(delay, ct));
    }

    private sealed class EchoChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default) => throw new NotSupportedException();
        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }
}
```

### Step 2: Run failing

```
dotnet test tests/AI.Sentinel.Tests --filter "PipelineForwarderIntegrationTests"
```
Expected: fail.

### Step 3: Modify `SentinelPipeline` ctor

Add `IEnumerable<IAuditForwarder>? forwarders = null` as a new optional parameter. Store as a private field (default to `Array.Empty<IAuditForwarder>()` if null). After every successful `_audit.AppendAsync(entry, ct)` site, add:

```csharp
foreach (var forwarder in _forwarders)
{
    // Fire-and-forget — never await, never throw
    _ = Task.Run(async () =>
    {
        try { await forwarder.SendAsync([entry], ct).ConfigureAwait(false); }
        catch { /* IAuditForwarder MUST NOT throw, but defend anyway */ }
    }, ct);
}
```

> **Why `Task.Run` instead of `_ = forwarder.SendAsync(...)`?** Because some forwarders (BufferingAuditForwarder.SendAsync) return synchronously after a `TryWrite`, but if a user registers a non-buffered forwarder that's slow, we don't want even the discard to wait. Using `Task.Run` decouples completely. Acceptable thread-pool cost — fire-and-forget per audit entry is rare relative to detection cost.

### Step 4: Update DI registration

In `ServiceCollectionExtensions.AddAISentinel(...)`, where `SentinelPipeline` is registered, ensure `IEnumerable<IAuditForwarder>` resolves from DI. Probably no code change needed — `services.GetServices<IAuditForwarder>()` works automatically once `SentinelPipeline` ctor accepts it.

### Step 5: Run tests

```
dotnet test tests/AI.Sentinel.Tests --filter "PipelineForwarderIntegrationTests"
```
Expected: 4 pass.

### Step 6: Run full suite

```
dotnet test tests/AI.Sentinel.Tests
```
Expected: 471 + 4 = 475 pass. No regressions.

### Step 7: Commit

```bash
git add src/AI.Sentinel/SentinelPipeline.cs \
        src/AI.Sentinel/ServiceCollectionExtensions.cs \
        tests/AI.Sentinel.Tests/Audit/PipelineForwarderIntegrationTests.cs
git commit -m "feat(audit): SentinelPipeline forwards every audit entry to registered IAuditForwarders"
```

---

## Task 3: `NdjsonFileAuditForwarder` (in core)

**Files:**
- Create: `src/AI.Sentinel/Audit/NdjsonFileAuditForwarder.cs`
- Create: `src/AI.Sentinel/Audit/NdjsonFileAuditForwarderOptions.cs`
- Create: `src/AI.Sentinel/Audit/AuditForwarderServiceCollectionExtensions.cs` — DI extensions for ALL forwarders (one place)
- Create: `tests/AI.Sentinel.Tests/Audit/NdjsonFileAuditForwarderTests.cs`

### Step 1: Write failing tests

```csharp
// tests/AI.Sentinel.Tests/Audit/NdjsonFileAuditForwarderTests.cs
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class NdjsonFileAuditForwarderTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(Path.GetTempPath(), $"sentinel-{Guid.NewGuid():N}.ndjson");

    public void Dispose() { try { File.Delete(_tempPath); } catch { } }

    private static AuditEntry MakeEntry(string id, string summary = "test") =>
        new() { Id = id, Timestamp = DateTimeOffset.UtcNow, Hash = "h", PreviousHash = null,
                Severity = Severity.Low, DetectorId = "T-01", Summary = summary };

    [Fact]
    public async Task SendAsync_AppendsLineToFile()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
            await f.SendAsync([MakeEntry("e1")], default);

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines);
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("e1", parsed.RootElement.GetProperty("Id").GetString());
    }

    [Fact]
    public async Task SendAsync_MultipleEntries_OneLinePerEntry()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
            await f.SendAsync([MakeEntry("e1"), MakeEntry("e2"), MakeEntry("e3")], default);

        var lines = File.ReadAllLines(_tempPath);
        Assert.Equal(3, lines.Length);
    }

    [Fact]
    public async Task SendAsync_NewlinesInSummary_EscapedNotBreakingFormat()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
            await f.SendAsync([MakeEntry("e1", "line1\nline2\nline3")], default);

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines); // newlines escaped, not literal in NDJSON
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("line1\nline2\nline3", parsed.RootElement.GetProperty("Summary").GetString());
    }

    [Fact]
    public async Task SendAsync_AppendMode_PreservesPriorContent()
    {
        File.WriteAllText(_tempPath, "{\"existing\":\"line\"}\n");

        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
            await f.SendAsync([MakeEntry("e1")], default);

        var lines = File.ReadAllLines(_tempPath);
        Assert.Equal(2, lines.Length);
        Assert.Contains("existing", lines[0], StringComparison.Ordinal);
    }
}
```

### Step 2: Run failing

```
dotnet test tests/AI.Sentinel.Tests --filter "NdjsonFileAuditForwarderTests"
```

### Step 3: Implement options

```csharp
// src/AI.Sentinel/Audit/NdjsonFileAuditForwarderOptions.cs
namespace AI.Sentinel.Audit;

public sealed class NdjsonFileAuditForwarderOptions
{
    /// <summary>Path to the NDJSON file. Appended to; created if missing.</summary>
    public string FilePath { get; set; } = "audit.ndjson";
}
```

### Step 4: Implement the forwarder

```csharp
// src/AI.Sentinel/Audit/NdjsonFileAuditForwarder.cs
using System.Text.Json;

namespace AI.Sentinel.Audit;

/// <summary>Audit forwarder that appends each entry as a JSON line to a local NDJSON file. Operators ship the file via Filebeat / Vector / Fluent Bit etc. Direct file append; no buffering needed.</summary>
public sealed class NdjsonFileAuditForwarder : IAuditForwarder, IAsyncDisposable
{
    private readonly FileStream _stream;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public NdjsonFileAuditForwarder(NdjsonFileAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.FilePath);
        _stream = new FileStream(options.FilePath, FileMode.Append, FileAccess.Write, FileShare.Read);
        _writer = new StreamWriter(_stream) { AutoFlush = false };
    }

    public async ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            foreach (var entry in batch)
            {
                var line = JsonSerializer.Serialize(entry, AuditJsonContext.Default.AuditEntry);
                await _writer.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false);
            }
            await _writer.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _writer.DisposeAsync().ConfigureAwait(false);
        await _stream.DisposeAsync().ConfigureAwait(false);
        _lock.Dispose();
    }
}
```

> **`AuditJsonContext`** — you may need to create a JSON source-gen context for `AuditEntry` if one doesn't exist. Check `src/AI.Sentinel/Audit/` for `*JsonContext.cs`. If absent, create it:
>
> ```csharp
> // src/AI.Sentinel/Audit/AuditJsonContext.cs
> using System.Text.Json.Serialization;
>
> namespace AI.Sentinel.Audit;
>
> [JsonSourceGenerationOptions(WriteIndented = false, PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified)]
> [JsonSerializable(typeof(AuditEntry))]
> internal partial class AuditJsonContext : JsonSerializerContext { }
> ```

### Step 5: Implement DI extension

```csharp
// src/AI.Sentinel/Audit/AuditForwarderServiceCollectionExtensions.cs
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Audit;

public static class AuditForwarderServiceCollectionExtensions
{
    /// <summary>Registers an <see cref="NdjsonFileAuditForwarder"/>. Direct file append; no buffering applied (file I/O is already fast).</summary>
    public static IServiceCollection AddSentinelNdjsonFileForwarder(
        this IServiceCollection services,
        Action<NdjsonFileAuditForwarderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);
        var opts = new NdjsonFileAuditForwarderOptions();
        configure(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAuditForwarder>(_ => new NdjsonFileAuditForwarder(opts));
        return services;
    }
}
```

### Step 6: Run tests + full suite

```
dotnet test tests/AI.Sentinel.Tests --filter "NdjsonFileAuditForwarderTests"
dotnet test tests/AI.Sentinel.Tests
```
Expected: 4 new pass; total 479.

### Step 7: Commit

```bash
git add src/AI.Sentinel/Audit/NdjsonFileAuditForwarder.cs \
        src/AI.Sentinel/Audit/NdjsonFileAuditForwarderOptions.cs \
        src/AI.Sentinel/Audit/AuditForwarderServiceCollectionExtensions.cs \
        src/AI.Sentinel/Audit/AuditJsonContext.cs \
        tests/AI.Sentinel.Tests/Audit/NdjsonFileAuditForwarderTests.cs
git commit -m "feat(audit): NdjsonFileAuditForwarder + AddSentinelNdjsonFileForwarder DI extension"
```

---

## Task 4: `SqliteAuditStore` (new package `AI.Sentinel.Sqlite`)

**Files:**
- Create: `src/AI.Sentinel.Sqlite/AI.Sentinel.Sqlite.csproj`
- Create: `src/AI.Sentinel.Sqlite/SqliteAuditStore.cs`
- Create: `src/AI.Sentinel.Sqlite/SqliteAuditStoreOptions.cs`
- Create: `src/AI.Sentinel.Sqlite/SqliteAuditStoreServiceCollectionExtensions.cs`
- Create: `src/AI.Sentinel.Sqlite/SqliteSchema.cs`
- Create: `tests/AI.Sentinel.Sqlite.Tests/AI.Sentinel.Sqlite.Tests.csproj`
- Create: `tests/AI.Sentinel.Sqlite.Tests/SqliteAuditStoreTests.cs`

### Step 0: Scaffold the new package

Look at `src/AI.Sentinel.AspNetCore/AI.Sentinel.AspNetCore.csproj` for an existing package's `.csproj` shape. Mirror it for `AI.Sentinel.Sqlite.csproj`:

```xml
<!-- src/AI.Sentinel.Sqlite/AI.Sentinel.Sqlite.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <PackageId>AI.Sentinel.Sqlite</PackageId>
    <Description>Persistent SQLite-backed audit store for AI.Sentinel.</Description>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\AI.Sentinel\AI.Sentinel.csproj" />
    <PackageReference Include="Microsoft.Data.Sqlite" Version="9.0.0" />
    <PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="9.0.0" />
  </ItemGroup>
</Project>
```

Update the solution file: `dotnet sln AI.Sentinel.sln add src/AI.Sentinel.Sqlite/AI.Sentinel.Sqlite.csproj`.

Same pattern for the test project — model after `tests/AI.Sentinel.AspNetCore.Tests/` if that exists, or wherever the test infra lives. Test project references both `AI.Sentinel.Sqlite` AND `AI.Sentinel.Tests` (for `Helpers/`).

### Step 1: Write failing tests

```csharp
// tests/AI.Sentinel.Sqlite.Tests/SqliteAuditStoreTests.cs
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using AI.Sentinel.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

public class SqliteAuditStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sentinel-{Guid.NewGuid():N}.db");

    public void Dispose() { try { File.Delete(_dbPath); } catch { } }

    private static AuditEntry Make(string id, string? prevHash = null) =>
        new() { Id = id, Timestamp = DateTimeOffset.UtcNow, Hash = $"h-{id}", PreviousHash = prevHash,
                Severity = Severity.High, DetectorId = "SEC-01", Summary = $"summary-{id}" };

    [Fact]
    public async Task Append_PersistsToFile_QueryReturnsAfterReopen()
    {
        var entry = Make("e1");

        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
            await store.AppendAsync(entry, default);

        await using (var reopened = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            var results = new List<AuditEntry>();
            await foreach (var e in reopened.QueryAsync(new AuditQuery(), default))
                results.Add(e);
            Assert.Single(results);
            Assert.Equal("e1", results[0].Id);
        }
    }

    [Fact]
    public async Task HashChain_PreviousHashLinksToLastEntryOnReopen()
    {
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
            await store.AppendAsync(Make("e1"), default);

        await using (var reopened = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            var lastHash = await reopened.GetLastHashForTestingAsync(default);
            Assert.Equal("h-e1", lastHash);
        }
    }

    [Fact]
    public async Task Query_FiltersBySeverityAndDetector()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        await store.AppendAsync(Make("e1") with { Severity = Severity.High, DetectorId = "SEC-01" }, default);
        await store.AppendAsync(Make("e2") with { Severity = Severity.Low,  DetectorId = "SEC-01" }, default);
        await store.AppendAsync(Make("e3") with { Severity = Severity.High, DetectorId = "SEC-02" }, default);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery
        {
            MinSeverity = Severity.High,
            DetectorId = "SEC-01",
        }, default)) results.Add(e);

        Assert.Single(results);
        Assert.Equal("e1", results[0].Id);
    }

    [Fact]
    public async Task ConcurrentAppends_AllPersisted_NoCorruption()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            store.AppendAsync(Make($"e{i}"), default).AsTask()));

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), default)) results.Add(e);
        Assert.Equal(50, results.Count);
    }

    [Fact]
    public async Task Schema_Version1_NewDatabaseInitialised()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });
        var version = await store.GetSchemaVersionForTestingAsync(default);
        Assert.Equal(1, version);
    }

    // Retention test would need clock-injection — defer if Time.Provider is not present.
}
```

### Step 2: Run failing

```
dotnet test tests/AI.Sentinel.Sqlite.Tests
```
Expected: fail — types not found.

### Step 3: Implement `SqliteAuditStoreOptions`

```csharp
// src/AI.Sentinel.Sqlite/SqliteAuditStoreOptions.cs
namespace AI.Sentinel.Sqlite;

public sealed class SqliteAuditStoreOptions
{
    /// <summary>Path to the SQLite database file. Created if missing.</summary>
    public string DatabasePath { get; set; } = "audit.db";

    /// <summary>Optional retention period; entries older than this are deleted by a background timer. Null = retain forever.</summary>
    public TimeSpan? RetentionPeriod { get; set; }
}
```

### Step 4: Implement schema bootstrap

```csharp
// src/AI.Sentinel.Sqlite/SqliteSchema.cs
using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Sqlite;

internal static class SqliteSchema
{
    internal const int CurrentVersion = 1;

    internal static async Task InitializeAsync(SqliteConnection conn, CancellationToken ct)
    {
        await using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
        await pragma.ExecuteNonQueryAsync(ct).ConfigureAwait(false);

        await using var versionCmd = conn.CreateCommand();
        versionCmd.CommandText = "PRAGMA user_version;";
        var current = (long)((await versionCmd.ExecuteScalarAsync(ct).ConfigureAwait(false)) ?? 0L);

        if (current < 1)
        {
            await using var migrate = conn.CreateCommand();
            migrate.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id            TEXT PRIMARY KEY,
                    timestamp     INTEGER NOT NULL,
                    severity      INTEGER NOT NULL,
                    detector_id   TEXT NOT NULL,
                    hash          TEXT NOT NULL,
                    previous_hash TEXT,
                    summary       TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries (timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_detector  ON audit_entries (detector_id);
                CREATE INDEX IF NOT EXISTS idx_audit_severity  ON audit_entries (severity);
                PRAGMA user_version = 1;
                """;
            await migrate.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }
}
```

### Step 5: Implement `SqliteAuditStore`

```csharp
// src/AI.Sentinel.Sqlite/SqliteAuditStore.cs
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Sqlite;

public sealed class SqliteAuditStore : IAuditStore, IAsyncDisposable
{
    private readonly SqliteConnection _conn;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Timer? _retentionTimer;
    private readonly TimeSpan? _retention;

    public SqliteAuditStore(SqliteAuditStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DatabasePath);

        var connStr = new SqliteConnectionStringBuilder
        {
            DataSource = options.DatabasePath,
            Pooling = false,
        }.ToString();
        _conn = new SqliteConnection(connStr);
        _conn.Open();
        SqliteSchema.InitializeAsync(_conn, default).GetAwaiter().GetResult();

        _retention = options.RetentionPeriod;
        if (_retention is { } r)
        {
            _retentionTimer = new Timer(_ => RunRetention(), null, TimeSpan.FromMinutes(1), TimeSpan.FromHours(1));
        }
    }

    public async ValueTask AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT OR REPLACE INTO audit_entries
                (id, timestamp, severity, detector_id, hash, previous_hash, summary)
                VALUES (@id, @ts, @sev, @det, @h, @ph, @sum);
                """;
            cmd.Parameters.AddWithValue("@id",  entry.Id);
            cmd.Parameters.AddWithValue("@ts",  entry.Timestamp.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("@sev", (int)entry.Severity);
            cmd.Parameters.AddWithValue("@det", entry.DetectorId);
            cmd.Parameters.AddWithValue("@h",   entry.Hash);
            cmd.Parameters.AddWithValue("@ph",  (object?)entry.PreviousHash ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@sum", entry.Summary);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        finally { _writeLock.Release(); }
    }

    public async IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await using var cmd = _conn.CreateCommand();
        var sql = "SELECT id, timestamp, severity, detector_id, hash, previous_hash, summary FROM audit_entries";
        var clauses = new List<string>();
        if (query.MinSeverity is { } min)  { clauses.Add("severity >= @sev"); cmd.Parameters.AddWithValue("@sev", (int)min); }
        if (query.DetectorId is not null)  { clauses.Add("detector_id = @det"); cmd.Parameters.AddWithValue("@det", query.DetectorId); }
        if (query.From is { } from)        { clauses.Add("timestamp >= @from"); cmd.Parameters.AddWithValue("@from", from.ToUnixTimeMilliseconds()); }
        if (query.To is { } to)            { clauses.Add("timestamp <= @to"); cmd.Parameters.AddWithValue("@to", to.ToUnixTimeMilliseconds()); }
        if (clauses.Count > 0) sql += " WHERE " + string.Join(" AND ", clauses);
        sql += " ORDER BY timestamp DESC";
        if (query.Limit is { } limit) { sql += " LIMIT @lim"; cmd.Parameters.AddWithValue("@lim", limit); }
        cmd.CommandText = sql;

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            yield return new AuditEntry
            {
                Id = reader.GetString(0),
                Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(1)),
                Severity = (Severity)reader.GetInt32(2),
                DetectorId = reader.GetString(3),
                Hash = reader.GetString(4),
                PreviousHash = reader.IsDBNull(5) ? null : reader.GetString(5),
                Summary = reader.GetString(6),
            };
        }
    }

    private void RunRetention()
    {
        if (_retention is null) return;
        try
        {
            _writeLock.Wait();
            try
            {
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "DELETE FROM audit_entries WHERE timestamp < @cutoff";
                cmd.Parameters.AddWithValue("@cutoff", DateTimeOffset.UtcNow.Subtract(_retention.Value).ToUnixTimeMilliseconds());
                cmd.ExecuteNonQuery();
            }
            finally { _writeLock.Release(); }
        }
        catch { /* swallow — retention is best-effort */ }
    }

    // Test-only helpers (internal — exposed via InternalsVisibleTo)
    internal async Task<string?> GetLastHashForTestingAsync(CancellationToken ct)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT hash FROM audit_entries ORDER BY timestamp DESC LIMIT 1";
        return (await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false)) as string;
    }

    internal async Task<int> GetSchemaVersionForTestingAsync(CancellationToken ct)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText = "PRAGMA user_version;";
        return Convert.ToInt32(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false));
    }

    public async ValueTask DisposeAsync()
    {
        _retentionTimer?.Dispose();
        await _conn.DisposeAsync().ConfigureAwait(false);
        _writeLock.Dispose();
    }
}
```

> **Adapt `AuditQuery`** — read `src/AI.Sentinel/Audit/AuditQuery.cs` (or wherever it lives) to confirm the shape (`MinSeverity`, `DetectorId`, `From`, `To`, `Limit`). Adjust the WHERE-clause builder to match actual properties.

### Step 6: Add `[InternalsVisibleTo("AI.Sentinel.Sqlite.Tests")]`

In `src/AI.Sentinel.Sqlite/AI.Sentinel.Sqlite.csproj` add:
```xml
<ItemGroup>
  <AssemblyAttribute Include="System.Runtime.CompilerServices.InternalsVisibleToAttribute">
    <_Parameter1>AI.Sentinel.Sqlite.Tests</_Parameter1>
  </AssemblyAttribute>
</ItemGroup>
```

### Step 7: DI extension

```csharp
// src/AI.Sentinel.Sqlite/SqliteAuditStoreServiceCollectionExtensions.cs
using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Sqlite;

public static class SqliteAuditStoreServiceCollectionExtensions
{
    /// <summary>Registers <see cref="SqliteAuditStore"/> as the <see cref="IAuditStore"/>. Replaces any previously registered store (last-registration-wins for IAuditStore).</summary>
    public static IServiceCollection AddSentinelSqliteStore(
        this IServiceCollection services,
        Action<SqliteAuditStoreOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);
        var opts = new SqliteAuditStoreOptions();
        configure(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAuditStore>(sp => new SqliteAuditStore(opts));
        return services;
    }
}
```

### Step 8: Run tests + full suite

```
dotnet test tests/AI.Sentinel.Sqlite.Tests
dotnet test tests/AI.Sentinel.Tests
```
Expected: ~5 new in Sqlite.Tests, no regressions in main suite.

### Step 9: Commit

```bash
git add src/AI.Sentinel.Sqlite/ \
        tests/AI.Sentinel.Sqlite.Tests/ \
        AI.Sentinel.sln
git commit -m "feat(audit): SqliteAuditStore — persistent audit storage in new AI.Sentinel.Sqlite package"
```

---

## Task 5: `AzureSentinelAuditForwarder` (new package `AI.Sentinel.AzureSentinel`)

**Files:**
- Create: `src/AI.Sentinel.AzureSentinel/AI.Sentinel.AzureSentinel.csproj`
- Create: `src/AI.Sentinel.AzureSentinel/AzureSentinelAuditForwarder.cs`
- Create: `src/AI.Sentinel.AzureSentinel/AzureSentinelAuditForwarderOptions.cs`
- Create: `src/AI.Sentinel.AzureSentinel/AzureSentinelServiceCollectionExtensions.cs`
- Create: `tests/AI.Sentinel.AzureSentinel.Tests/AI.Sentinel.AzureSentinel.Tests.csproj`
- Create: `tests/AI.Sentinel.AzureSentinel.Tests/AzureSentinelAuditForwarderTests.cs`

### Step 0: Scaffold the package

Same shape as Task 4 but with `Azure.Monitor.Ingestion` + `Azure.Identity`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <PackageId>AI.Sentinel.AzureSentinel</PackageId>
    <Description>Forward AI.Sentinel audit entries to Azure Sentinel via the Logs Ingestion API.</Description>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\AI.Sentinel\AI.Sentinel.csproj" />
    <PackageReference Include="Azure.Monitor.Ingestion" Version="1.1.2" />
    <PackageReference Include="Azure.Identity" Version="1.13.1" />
    <PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="9.0.0" />
  </ItemGroup>
</Project>
```

`dotnet sln AI.Sentinel.sln add src/AI.Sentinel.AzureSentinel/...`

### Step 1: Write failing tests (with stub `LogsIngestionClient`)

```csharp
// tests/AI.Sentinel.AzureSentinel.Tests/AzureSentinelAuditForwarderTests.cs
using AI.Sentinel.Audit;
using AI.Sentinel.AzureSentinel;
using AI.Sentinel.Domain;
using Azure;
using Azure.Monitor.Ingestion;
using Xunit;

namespace AI.Sentinel.AzureSentinel.Tests;

public class AzureSentinelAuditForwarderTests
{
    private static AuditEntry MakeEntry(string id) => new()
    {
        Id = id, Timestamp = DateTimeOffset.UtcNow,
        Hash = $"h-{id}", PreviousHash = null,
        Severity = Severity.High, DetectorId = "SEC-01", Summary = $"summary-{id}",
    };

    [Fact]
    public async Task SendAsync_CallsUploadOnce_WithCorrectBatch()
    {
        var stub = new RecordingClient();
        var f = new AzureSentinelAuditForwarder(stub, new AzureSentinelAuditForwarderOptions
        {
            DcrEndpoint = new Uri("https://dce.example.com"),
            DcrImmutableId = "dcr-abc",
            StreamName = "Custom-AISentinelAudit_CL",
        });

        await f.SendAsync([MakeEntry("e1"), MakeEntry("e2")], default);

        Assert.Single(stub.Uploads);
        Assert.Equal("dcr-abc", stub.Uploads[0].RuleId);
        Assert.Equal("Custom-AISentinelAudit_CL", stub.Uploads[0].StreamName);
        Assert.Equal(2, stub.Uploads[0].Count);
    }

    [Fact]
    public async Task SendAsync_RequestFailedException_Swallowed_NotPropagated()
    {
        var stub = new ThrowingClient();
        var f = new AzureSentinelAuditForwarder(stub, new AzureSentinelAuditForwarderOptions
        {
            DcrEndpoint = new Uri("https://dce.example.com"),
            DcrImmutableId = "dcr-abc",
            StreamName = "Custom-AISentinelAudit_CL",
        });

        // Must not throw
        await f.SendAsync([MakeEntry("e1")], default);
    }

    [Fact]
    public void Construction_MissingDcrImmutableId_Throws()
    {
        var stub = new RecordingClient();
        Assert.Throws<ArgumentException>(() => new AzureSentinelAuditForwarder(stub, new AzureSentinelAuditForwarderOptions
        {
            DcrEndpoint = new Uri("https://dce.example.com"),
            DcrImmutableId = "",
            StreamName = "stream",
        }));
    }

    private sealed class RecordingClient : ILogsIngestionClientWrapper
    {
        public List<(string RuleId, string StreamName, int Count)> Uploads { get; } = new();
        public Task UploadAsync(string ruleId, string streamName, IEnumerable<AuditEntry> entries, CancellationToken ct)
        {
            Uploads.Add((ruleId, streamName, entries.Count()));
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingClient : ILogsIngestionClientWrapper
    {
        public Task UploadAsync(string ruleId, string streamName, IEnumerable<AuditEntry> entries, CancellationToken ct)
            => throw new RequestFailedException("boom");
    }
}
```

### Step 2: Run failing

### Step 3: Implement the wrapper interface (for testability)

The forwarder takes a wrapper interface so tests can stub it:

```csharp
// src/AI.Sentinel.AzureSentinel/ILogsIngestionClientWrapper.cs
namespace AI.Sentinel.AzureSentinel;

internal interface ILogsIngestionClientWrapper
{
    Task UploadAsync(string ruleId, string streamName, IEnumerable<Audit.AuditEntry> entries, CancellationToken ct);
}

internal sealed class LogsIngestionClientWrapper(Azure.Monitor.Ingestion.LogsIngestionClient client) : ILogsIngestionClientWrapper
{
    public async Task UploadAsync(string ruleId, string streamName, IEnumerable<Audit.AuditEntry> entries, CancellationToken ct)
        => await client.UploadAsync(ruleId, streamName, entries.ToList(), null, ct).ConfigureAwait(false);
}
```

Add `[InternalsVisibleTo("AI.Sentinel.AzureSentinel.Tests")]` to the csproj.

### Step 4: Implement the forwarder + options

```csharp
// src/AI.Sentinel.AzureSentinel/AzureSentinelAuditForwarderOptions.cs
using Azure.Core;

namespace AI.Sentinel.AzureSentinel;

public sealed class AzureSentinelAuditForwarderOptions
{
    public Uri DcrEndpoint { get; set; } = null!;
    public string DcrImmutableId { get; set; } = null!;
    public string StreamName { get; set; } = null!;

    /// <summary>Default: <c>new DefaultAzureCredential()</c>.</summary>
    public TokenCredential? Credential { get; set; }
}
```

```csharp
// src/AI.Sentinel.AzureSentinel/AzureSentinelAuditForwarder.cs
using AI.Sentinel.Audit;
using AI.Sentinel.Mcp.Logging;

namespace AI.Sentinel.AzureSentinel;

public sealed class AzureSentinelAuditForwarder : IAuditForwarder
{
    private readonly ILogsIngestionClientWrapper _client;
    private readonly string _ruleId;
    private readonly string _streamName;

    internal AzureSentinelAuditForwarder(ILogsIngestionClientWrapper client, AzureSentinelAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DcrImmutableId);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.StreamName);
        ArgumentNullException.ThrowIfNull(options.DcrEndpoint);
        _client = client;
        _ruleId = options.DcrImmutableId;
        _streamName = options.StreamName;
    }

    public AzureSentinelAuditForwarder(AzureSentinelAuditForwarderOptions options)
        : this(new LogsIngestionClientWrapper(
                new Azure.Monitor.Ingestion.LogsIngestionClient(
                    options.DcrEndpoint,
                    options.Credential ?? new Azure.Identity.DefaultAzureCredential())),
               options) { }

    public async ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        try
        {
            await _client.UploadAsync(_ruleId, _streamName, batch, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"]  = "audit_forward",
                ["action"] = "send_error",
                ["forwarder"] = "AzureSentinel",
                ["error"]  = ex.GetType().Name,
            });
        }
    }
}
```

### Step 5: DI extension (auto-buffering)

```csharp
// src/AI.Sentinel.AzureSentinel/AzureSentinelServiceCollectionExtensions.cs
using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.AzureSentinel;

public static class AzureSentinelServiceCollectionExtensions
{
    /// <summary>Registers an <see cref="AzureSentinelAuditForwarder"/> wrapped with <see cref="BufferingAuditForwarder{T}"/> (defaults: batch=100, interval=5s). Per-entry HTTP roundtrips are unworkable; buffering is mandatory for SIEM ingestion.</summary>
    public static IServiceCollection AddSentinelAzureSentinelForwarder(
        this IServiceCollection services,
        Action<AzureSentinelAuditForwarderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);
        var opts = new AzureSentinelAuditForwarderOptions();
        configure(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAuditForwarder>(_ =>
            new BufferingAuditForwarder<AzureSentinelAuditForwarder>(
                new AzureSentinelAuditForwarder(opts),
                new BufferingAuditForwarderOptions()));
        return services;
    }
}
```

### Step 6: Run tests + full suite + commit

```
dotnet test tests/AI.Sentinel.AzureSentinel.Tests
dotnet test tests/AI.Sentinel.Tests
```

```bash
git add src/AI.Sentinel.AzureSentinel/ \
        tests/AI.Sentinel.AzureSentinel.Tests/ \
        AI.Sentinel.sln
git commit -m "feat(audit): AzureSentinelAuditForwarder — Logs Ingestion API forwarding in new AI.Sentinel.AzureSentinel package"
```

---

## Task 6: `OpenTelemetryAuditForwarder` (new package `AI.Sentinel.OpenTelemetry`)

**Files:**
- Create: `src/AI.Sentinel.OpenTelemetry/AI.Sentinel.OpenTelemetry.csproj`
- Create: `src/AI.Sentinel.OpenTelemetry/OpenTelemetryAuditForwarder.cs`
- Create: `src/AI.Sentinel.OpenTelemetry/OpenTelemetryAuditForwarderOptions.cs`
- Create: `src/AI.Sentinel.OpenTelemetry/OpenTelemetryServiceCollectionExtensions.cs`
- Create: `tests/AI.Sentinel.OpenTelemetry.Tests/AI.Sentinel.OpenTelemetry.Tests.csproj`
- Create: `tests/AI.Sentinel.OpenTelemetry.Tests/OpenTelemetryAuditForwarderTests.cs`

### Step 0: Scaffold

Dependencies: `OpenTelemetry`, `OpenTelemetry.Logs`, `Microsoft.Extensions.Logging.Abstractions`. Same package shape as Task 4 / 5.

### Step 1: Write failing tests using `InMemoryExporter`

```csharp
// tests/AI.Sentinel.OpenTelemetry.Tests/OpenTelemetryAuditForwarderTests.cs
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using AI.Sentinel.OpenTelemetry;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using Xunit;

namespace AI.Sentinel.OpenTelemetry.Tests;

public class OpenTelemetryAuditForwarderTests
{
    private static AuditEntry Make(string id, Severity sev = Severity.High) =>
        new() { Id = id, Timestamp = DateTimeOffset.UtcNow, Hash = $"h-{id}", PreviousHash = "prev",
                Severity = sev, DetectorId = "SEC-01", Summary = $"summary-{id}" };

    [Fact]
    public async Task SendAsync_EmitsOneLogRecordPerEntry()
    {
        var records = new List<LogRecord>();
        var loggerFactory = LoggerFactory.Create(b => b.AddOpenTelemetry(o =>
            o.AddInMemoryExporter(records)));

        var f = new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions { LoggerFactory = loggerFactory });
        await f.SendAsync([Make("e1"), Make("e2"), Make("e3")], default);

        loggerFactory.Dispose(); // forces flush
        Assert.Equal(3, records.Count);
    }

    [Theory]
    [InlineData(Severity.Critical, LogLevel.Critical)]
    [InlineData(Severity.High,     LogLevel.Error)]
    [InlineData(Severity.Medium,   LogLevel.Warning)]
    [InlineData(Severity.Low,      LogLevel.Information)]
    [InlineData(Severity.None,     LogLevel.Debug)]
    public async Task SendAsync_SeverityMapsToLogLevel(Severity sev, LogLevel expected)
    {
        var records = new List<LogRecord>();
        var loggerFactory = LoggerFactory.Create(b => b
            .SetMinimumLevel(LogLevel.Trace)
            .AddOpenTelemetry(o => o.AddInMemoryExporter(records)));

        var f = new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions { LoggerFactory = loggerFactory });
        await f.SendAsync([Make("e1", sev)], default);

        loggerFactory.Dispose();
        Assert.Single(records);
        Assert.Equal(expected, records[0].LogLevel);
    }

    [Fact]
    public async Task SendAsync_AuditEntryFieldsLiftedAsAttributes()
    {
        var records = new List<LogRecord>();
        var loggerFactory = LoggerFactory.Create(b => b.AddOpenTelemetry(o => o.AddInMemoryExporter(records)));

        var f = new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions { LoggerFactory = loggerFactory });
        await f.SendAsync([Make("e1")], default);
        loggerFactory.Dispose();

        Assert.Single(records);
        var attrs = records[0].Attributes!.ToDictionary(kv => kv.Key, kv => kv.Value);
        Assert.Equal("e1", attrs["audit.id"]);
        Assert.Equal("SEC-01", attrs["audit.detector_id"]);
        Assert.Equal("h-e1", attrs["audit.hash"]);
        Assert.Equal("prev", attrs["audit.previous_hash"]);
    }
}
```

### Step 2: Run failing

### Step 3: Implement options

```csharp
// src/AI.Sentinel.OpenTelemetry/OpenTelemetryAuditForwarderOptions.cs
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.OpenTelemetry;

public sealed class OpenTelemetryAuditForwarderOptions
{
    public ILoggerFactory? LoggerFactory { get; set; }
    public string CategoryName { get; set; } = "AI.Sentinel.Audit";
}
```

### Step 4: Implement forwarder

```csharp
// src/AI.Sentinel.OpenTelemetry/OpenTelemetryAuditForwarder.cs
using AI.Sentinel.Audit;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.OpenTelemetry;

public sealed class OpenTelemetryAuditForwarder : IAuditForwarder
{
    private readonly ILogger _logger;

    public OpenTelemetryAuditForwarder(OpenTelemetryAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var factory = options.LoggerFactory
            ?? throw new ArgumentException("LoggerFactory must be set", nameof(options));
        _logger = factory.CreateLogger(options.CategoryName);
    }

    public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        foreach (var entry in batch)
        {
            var level = MapSeverity(entry.Severity);
            using (_logger.BeginScope(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["audit.id"]            = entry.Id,
                ["audit.detector_id"]   = entry.DetectorId,
                ["audit.severity"]      = entry.Severity.ToString(),
                ["audit.hash"]          = entry.Hash,
                ["audit.previous_hash"] = entry.PreviousHash,
                ["audit.timestamp"]     = entry.Timestamp.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            }))
            {
                _logger.Log(level, "{Summary}", entry.Summary);
            }
        }
        return ValueTask.CompletedTask;
    }

    private static LogLevel MapSeverity(Domain.Severity sev) => sev switch
    {
        Domain.Severity.Critical => LogLevel.Critical,
        Domain.Severity.High     => LogLevel.Error,
        Domain.Severity.Medium   => LogLevel.Warning,
        Domain.Severity.Low      => LogLevel.Information,
        _                        => LogLevel.Debug,
    };
}
```

### Step 5: DI extension (no auto-buffering)

```csharp
// src/AI.Sentinel.OpenTelemetry/OpenTelemetryServiceCollectionExtensions.cs
using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.OpenTelemetry;

public static class OpenTelemetryServiceCollectionExtensions
{
    /// <summary>Registers an <see cref="OpenTelemetryAuditForwarder"/>. Does NOT wrap with BufferingAuditForwarder — the OTel SDK's BatchExportProcessor handles batching.</summary>
    public static IServiceCollection AddSentinelOpenTelemetryForwarder(
        this IServiceCollection services,
        Action<OpenTelemetryAuditForwarderOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IAuditForwarder>(sp =>
        {
            var opts = new OpenTelemetryAuditForwarderOptions
            {
                LoggerFactory = sp.GetRequiredService<ILoggerFactory>(),
            };
            configure?.Invoke(opts);
            return new OpenTelemetryAuditForwarder(opts);
        });
        return services;
    }
}
```

### Step 6: Run tests + commit

```bash
git add src/AI.Sentinel.OpenTelemetry/ \
        tests/AI.Sentinel.OpenTelemetry.Tests/ \
        AI.Sentinel.sln
git commit -m "feat(audit): OpenTelemetryAuditForwarder — vendor-neutral via OTel collector in new AI.Sentinel.OpenTelemetry package"
```

---

## Task 7: README + BACKLOG cleanup

**Files:**
- Modify: `README.md` — new Audit subsection (storage backends + forwarders)
- Modify: `docs/BACKLOG.md` — remove "Persistent audit store" item; add 7 follow-ups

### Step 1: Update `README.md`

Add a new top-level section (similar shape to the IToolCallGuard section). Cover:
- Default behaviour: in-memory ring buffer, no forwarders
- `AddSentinelSqliteStore(...)` for persistent storage
- The 3 forwarders + their DI extensions + which ones auto-buffer
- A complete worked example showing SQLite + Azure Sentinel + OpenTelemetry forwarders together

Place it after the existing Tool-Call Authorization section, before Configuration.

### Step 2: Update `docs/BACKLOG.md`

**REMOVE:** the `Persistent audit store` row (now shipped via `AI.Sentinel.Sqlite`).

**ADD** these 7 follow-ups (see design doc's Backlog Updates section for full text):
1. `AI.Sentinel.Postgres`
2. `SplunkHecAuditForwarder`
3. `GenericWebhookAuditForwarder`
4. NDJSON file rotation
5. `MaxDatabaseSizeBytes` cap on `SqliteAuditStore`
6. Live integration test for `AzureSentinelAuditForwarder` (CI secret)
7. Live OTel collector integration test

### Step 3: Run full suite to confirm no regressions

```
dotnet build
dotnet test tests/AI.Sentinel.Tests
dotnet test tests/AI.Sentinel.Sqlite.Tests
dotnet test tests/AI.Sentinel.AzureSentinel.Tests
dotnet test tests/AI.Sentinel.OpenTelemetry.Tests
```

### Step 4: Commit

```bash
git add README.md docs/BACKLOG.md
git commit -m "docs: persistent audit store + forwarders README section + backlog cleanup"
```

---

## Final review checklist

After Task 7, dispatch the `superpowers:code-reviewer` agent for cross-cutting review against:
- The design doc
- This plan
- Existing AI.Sentinel conventions (MA0002/MA0006 ordinal-string, no XML doc noise, fail-open posture)
- All 4 backlog items closed (persistent store + 3 forwarders)

Then run `superpowers:finishing-a-development-branch`.

**Total estimated scope:** 1 new interface + 1 buffering decorator (~150 LOC core), 1 NDJSON forwarder (~80 LOC core), 3 new packages each ~150 LOC, ~30 new tests across 4 test projects. 7 tasks, should land in a focused multi-hour session.
