# ZeroAlloc Native Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire ZeroAlloc.Results, ZeroAlloc.Inject, and ZeroAlloc.Rest natively into AI.Sentinel so that the primary API returns `Result<ChatResponse, SentinelError>` rather than throwing, detectors self-register via source-generated DI, and threats can optionally fire a REST webhook.

**Architecture:** `SentinelPipeline` becomes the primary class with a clean `Result<ChatResponse, SentinelError>` return type. `SentinelChatClient` is demoted to a thin `IChatClient` compatibility shim. Each of the 43 detectors gains a `[Singleton]` attribute that drives compile-time DI registration via `ZeroAlloc.Inject.Generator`, replacing the three explicit registration methods.

**Tech Stack:** C# 13 / .NET 8+9, ZeroAlloc.Results 0.1.*, ZeroAlloc.Inject (local project reference during dev), ZeroAlloc.Rest (local project reference during dev), xUnit, dotnet test.

---

## Task 1: Add ZeroAlloc.Inject package reference

**Files:**
- Modify: `src/AI.Sentinel/AI.Sentinel.csproj`

**Step 1: Add the package references**

In `AI.Sentinel.csproj`, inside the existing `<ItemGroup>` with other ZeroAlloc references, add:

```xml
<PackageReference Include="ZeroAlloc.Inject" Version="1.*" />
<PackageReference Include="ZeroAlloc.Inject.Generator" Version="1.*"
                  OutputItemType="Analyzer"
                  ReferenceOutputAssembly="false" />
```

Also add the assembly-level attribute at the bottom of the `<ItemGroup>` (or create a new one) — this tells the generator what extension method name to emit:

Nothing to add in csproj for the attribute — that goes in a `.cs` file (see Task 2).

**Step 2: Verify build still passes**

```
cd src/AI.Sentinel
dotnet build
```

Expected: builds with no new errors (generator runs but emits nothing yet — no `[Singleton]` attributes in scope).

**Step 3: Commit**

```bash
git add src/AI.Sentinel/AI.Sentinel.csproj
git commit -m "feat: add ZeroAlloc.Inject package reference"
```

---

## Task 2: Emit the assembly attribute for the generated extension method

**Files:**
- Create: `src/AI.Sentinel/AssemblyAttributes.cs`

**Step 1: Create the file**

```csharp
using ZeroAlloc.Inject;

[assembly: ZeroAllocInject("AddAISentinelDetectors")]
```

This tells the generator to emit a `IServiceCollection.AddAISentinelDetectors()` extension method covering all classes annotated with `[Singleton]` / `[Transient]` / `[Scoped]` in this assembly.

**Step 2: Build to confirm generator is active**

```
dotnet build src/AI.Sentinel
```

Expected: builds clean. The generator emits an empty method body (no services yet).

**Step 3: Commit**

```bash
git add src/AI.Sentinel/AssemblyAttributes.cs
git commit -m "feat: declare ZeroAllocInject assembly attribute"
```

---

## Task 3: Annotate all security detectors with [Singleton]

**Files to modify** (22 files in `src/AI.Sentinel/Detectors/Security/`):
- `PromptInjectionDetector.cs`, `CredentialExposureDetector.cs`, `ToolPoisoningDetector.cs`, `DataExfiltrationDetector.cs`, `JailbreakDetector.cs`, `PrivilegeEscalationDetector.cs`, `CovertChannelDetector.cs`, `EntropyCovertChannelDetector.cs`, `IndirectInjectionDetector.cs`, `AgentImpersonationDetector.cs`, `MemoryCorruptionDetector.cs`, `UnauthorizedAccessDetector.cs`, `ShadowServerDetector.cs`, `InformationFlowDetector.cs`, `PhantomCitationSecurityDetector.cs`, `GovernanceGapDetector.cs`, `SupplyChainPoisoningDetector.cs`, `PiiLeakageDetector.cs`, `AdversarialUnicodeDetector.cs`, `CodeInjectionDetector.cs`, `PromptTemplateLeakageDetector.cs`, `LanguageSwitchAttackDetector.cs`, `RefusalBypassDetector.cs`

**Step 1: Add attribute to each detector**

For every file above, add the `using ZeroAlloc.Inject;` using and the `[Singleton(As = typeof(IDetector), AllowMultiple = true)]` attribute on the class. Example for `PromptInjectionDetector.cs`:

Before:
```csharp
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class PromptInjectionDetector : IDetector
```

After:
```csharp
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class PromptInjectionDetector : IDetector
```

Apply the same pattern to all 23 security detector files.

**Step 2: Build**

```
dotnet build src/AI.Sentinel
```

Expected: builds clean.

**Step 3: Commit**

```bash
git add src/AI.Sentinel/Detectors/Security/
git commit -m "feat: annotate security detectors with [Singleton] for DI generation"
```

---

## Task 4: Annotate all hallucination and operational detectors with [Singleton]

**Files to modify** (20 files):

Hallucination (`src/AI.Sentinel/Detectors/Hallucination/`):
- `PhantomCitationDetector.cs`, `SelfConsistencyDetector.cs`, `CrossAgentContradictionDetector.cs`, `SourceGroundingDetector.cs`, `ConfidenceDecayDetector.cs`, `StaleKnowledgeDetector.cs`, `IntraSessionContradictionDetector.cs`, `GroundlessStatisticDetector.cs`

Operational (`src/AI.Sentinel/Detectors/Operational/`):
- `BlankResponseDetector.cs`, `RepetitionLoopDetector.cs`, `IncompleteCodeBlockDetector.cs`, `PlaceholderTextDetector.cs`, `ContextCollapseDetector.cs`, `AgentProbingDetector.cs`, `QueryIntentDetector.cs`, `ResponseCoherenceDetector.cs`, `SemanticRepetitionDetector.cs`, `PersonaDriftDetector.cs`, `SycophancyDetector.cs`, `WrongLanguageDetector.cs`

**Step 1: Add attribute to each detector**

Same pattern as Task 3 — add `using ZeroAlloc.Inject;` and `[Singleton(As = typeof(IDetector), AllowMultiple = true)]` to every class.

**Step 2: Build**

```
dotnet build src/AI.Sentinel
```

Expected: builds clean. The generator now emits `AddAISentinelDetectors()` registering all 43 detectors.

**Step 3: Commit**

```bash
git add src/AI.Sentinel/Detectors/Hallucination/ src/AI.Sentinel/Detectors/Operational/
git commit -m "feat: annotate hallucination and operational detectors with [Singleton]"
```

---

## Task 5: Replace explicit registration with generated method

**Files:**
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`

**Step 1: Write a test that the pipeline is populated after DI**

In `tests/AI.Sentinel.Tests/ServiceCollectionExtensionsTests.cs` (create if not exists):

```csharp
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAISentinel_RegistersAllDetectors()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var provider = services.BuildServiceProvider();

        var detectors = provider.GetServices<IDetector>().ToList();
        Assert.True(detectors.Count >= 43, $"Expected >= 43 detectors, got {detectors.Count}");
    }
}
```

**Step 2: Run test to verify it currently passes (baseline)**

```
dotnet test tests/AI.Sentinel.Tests --filter "ServiceCollectionExtensionsTests"
```

Expected: PASS (explicit registration still in place).

**Step 3: Replace the three explicit registration methods**

In `ServiceCollectionExtensions.cs`, replace the calls to `RegisterDetectors(services)` and delete the three private methods `RegisterDetectors`, `RegisterSecurityDetectors`, `RegisterHallucinationDetectors`, `RegisterOperationalDetectors`.

Replace with:

```csharp
services.AddAISentinelDetectors(); // source-generated by ZeroAlloc.Inject
```

The full `AddAISentinel` method body becomes:

```csharp
public static IServiceCollection AddAISentinel(
    this IServiceCollection services,
    Action<SentinelOptions>? configure = null)
{
    var opts = new SentinelOptions();
    configure?.Invoke(opts);
    services.AddSingleton(opts);
    services.AddSingleton<IAuditStore>(new RingBufferAuditStore(opts.AuditCapacity));
    services.AddSingleton(sp => new InterventionEngine(
        opts,
        mediator: sp.GetService<IMediator>(),
        logger: sp.GetService<ILogger<InterventionEngine>>()));

    services.AddAISentinelDetectors();

    services.AddSingleton(sp =>
        new DetectionPipeline(sp.GetServices<IDetector>(), opts.EscalationClient, sp.GetService<ILogger<DetectionPipeline>>()));

    return services;
}
```

Delete the entire `RegisterDetectors`, `RegisterSecurityDetectors`, `RegisterHallucinationDetectors`, `RegisterOperationalDetectors` methods.

**Step 4: Run test again**

```
dotnet test tests/AI.Sentinel.Tests --filter "ServiceCollectionExtensionsTests"
```

Expected: PASS.

**Step 5: Run full test suite**

```
dotnet test tests/AI.Sentinel.Tests
```

Expected: all tests pass.

**Step 6: Commit**

```bash
git add src/AI.Sentinel/ServiceCollectionExtensions.cs tests/AI.Sentinel.Tests/ServiceCollectionExtensionsTests.cs
git commit -m "feat: replace explicit detector registration with ZeroAlloc.Inject generated method"
```

---

## Task 6: Define SentinelError

**Files:**
- Create: `src/AI.Sentinel/SentinelError.cs`

**Step 1: Write a failing test**

In `tests/AI.Sentinel.Tests/SentinelErrorTests.cs`:

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelErrorTests
{
    [Fact]
    public void ThreatDetected_ToException_ReturnsSentinelException()
    {
        var result = DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test");
        var error = new SentinelError.ThreatDetected(result, SentinelAction.Quarantine);
        var ex = error.ToException();
        Assert.IsType<SentinelException>(ex);
        Assert.Contains("SEC-01", ex.Message);
    }

    [Fact]
    public void PipelineFailure_ToException_ReturnsException()
    {
        var error = new SentinelError.PipelineFailure("something went wrong");
        var ex = error.ToException();
        Assert.Contains("something went wrong", ex.Message);
    }
}
```

**Step 2: Run to verify FAIL**

```
dotnet test tests/AI.Sentinel.Tests --filter "SentinelErrorTests"
```

Expected: FAIL — `SentinelError` does not exist yet.

**Step 3: Create SentinelError.cs**

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;

namespace AI.Sentinel;

public abstract record SentinelError
{
    public sealed record ThreatDetected(DetectionResult Result, SentinelAction Action) : SentinelError;
    public sealed record PipelineFailure(string Message, Exception? Inner = null) : SentinelError;

    public Exception ToException() => this switch
    {
        ThreatDetected t => new SentinelException(
            $"AI.Sentinel quarantined message: {t.Result.Severity} threat detected by {t.Result.DetectorId}.",
            t.Result),
        PipelineFailure f => new InvalidOperationException(f.Message, f.Inner),
        _ => new InvalidOperationException("Unknown SentinelError")
    };
}
```

Note: `SentinelException(string, DetectionResult)` — add this constructor to `SentinelException.cs` if it doesn't exist. The current constructor takes `PipelineResult`. Add an overload:

```csharp
public SentinelException(string message, DetectionResult result) : base(message)
    => PipelineResult = new PipelineResult(ThreatRiskScore.Zero, [result]);
```

**Step 4: Run test**

```
dotnet test tests/AI.Sentinel.Tests --filter "SentinelErrorTests"
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/AI.Sentinel/SentinelError.cs src/AI.Sentinel/Intervention/SentinelException.cs tests/AI.Sentinel.Tests/SentinelErrorTests.cs
git commit -m "feat: add SentinelError discriminated union with ToException()"
```

---

## Task 7: Create SentinelPipeline (non-streaming)

**Files:**
- Create: `src/AI.Sentinel/SentinelPipeline.cs`
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`

**Step 1: Write failing test**

In `tests/AI.Sentinel.Tests/SentinelPipelineTests.cs`:

```csharp
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using Xunit;
using ZeroAlloc.Results;

namespace AI.Sentinel.Tests;

public class SentinelPipelineTests
{
    private static SentinelPipeline BuildCleanPipeline()
    {
        var opts = new SentinelOptions();
        var pipeline = new DetectionPipeline([], null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        var inner = new TestChatClient("hello");
        return new SentinelPipeline(inner, pipeline, audit, engine, opts);
    }

    [Fact]
    public async Task GetResponseResultAsync_CleanMessage_ReturnsSuccess()
    {
        var pipeline = BuildCleanPipeline();
        var result = await pipeline.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], null, default);
        Assert.True(result.IsSuccess);
    }

    private sealed class TestChatClient(string reply) : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, reply)]));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => throw new NotImplementedException();

        public ChatClientMetadata Metadata => new("test", null, null);
        public TService? GetService<TService>(object? key = null) where TService : class => null;
        public void Dispose() { }
    }
}
```

**Step 2: Run to verify FAIL**

```
dotnet test tests/AI.Sentinel.Tests --filter "SentinelPipelineTests"
```

Expected: FAIL — `SentinelPipeline` does not exist.

**Step 3: Create SentinelPipeline.cs**

```csharp
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using ZeroAlloc.Results;

namespace AI.Sentinel;

public sealed class SentinelPipeline(
    IChatClient innerClient,
    DetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options)
{
    public async ValueTask<Result<ChatResponse, SentinelError>> GetResponseResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
    {
        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var sessionId = SessionId.New();

        var promptResult = await ScanAsync(messageList, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct).ConfigureAwait(false);
        if (promptResult is not null)
            return Result<ChatResponse, SentinelError>.Failure(promptResult);

        ChatResponse response;
        try
        {
            response = await innerClient.GetResponseAsync(messageList, chatOptions, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return Result<ChatResponse, SentinelError>.Failure(
                new SentinelError.PipelineFailure("Inner client failed.", ex));
        }

        IReadOnlyList<ChatMessage> responseMessages =
            response.Messages as IReadOnlyList<ChatMessage> ?? response.Messages.ToList();
        var responseResult = await ScanAsync(responseMessages, sessionId,
            options.DefaultReceiverId, options.DefaultSenderId, ct).ConfigureAwait(false);
        if (responseResult is not null)
            return Result<ChatResponse, SentinelError>.Failure(responseResult);

        return Result<ChatResponse, SentinelError>.Success(response);
    }

    private async ValueTask<SentinelError?> ScanAsync(
        IReadOnlyList<ChatMessage> msgs,
        SessionId sessionId,
        AgentId sender,
        AgentId receiver,
        CancellationToken ct)
    {
        var ctx = new SentinelContext(sender, receiver, sessionId, msgs, []);
        var pipelineResult = await pipeline.RunAsync(ctx, ct).ConfigureAwait(false);
        await AppendAuditAsync(pipelineResult, msgs, ct).ConfigureAwait(false);

        if (pipelineResult.IsClean) return null;

        var action = options.ActionFor(pipelineResult.MaxSeverity);
        PublishNotifications(pipelineResult, sessionId, sender, receiver, action);

        if (action == SentinelAction.Quarantine)
        {
            var top = pipelineResult.Detections.FirstOrDefault()
                ?? DetectionResult.Clean(new DetectorId("unknown"));
            return new SentinelError.ThreatDetected(top, action);
        }
        return null;
    }

    private void PublishNotifications(
        PipelineResult result,
        SessionId sessionId,
        AgentId sender,
        AgentId receiver,
        SentinelAction action)
        => interventionEngine.Apply(result, sessionId, sender, receiver);

    private async Task AppendAuditAsync(
        PipelineResult result,
        IReadOnlyList<ChatMessage> msgs,
        CancellationToken ct)
    {
        var content = msgs.LastOrDefault()?.Text ?? "";
        var hash = ComputeHash(content);
        foreach (var detection in result.Detections)
        {
            var entry = new AuditEntry(
                Guid.NewGuid().ToString("N"),
                DateTimeOffset.UtcNow,
                hash, null,
                detection.Severity,
                detection.DetectorId.ToString(),
                detection.Reason);
            await auditStore.AppendAsync(entry, ct).ConfigureAwait(false);
        }
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
```

**Step 4: Run test**

```
dotnet test tests/AI.Sentinel.Tests --filter "SentinelPipelineTests"
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/AI.Sentinel/SentinelPipeline.cs tests/AI.Sentinel.Tests/SentinelPipelineTests.cs
git commit -m "feat: add SentinelPipeline with Result-returning GetResponseResultAsync"
```

---

## Task 8: Refactor SentinelChatClient to delegate to SentinelPipeline

**Files:**
- Modify: `src/AI.Sentinel/SentinelChatClient.cs`

**Step 1: Run existing tests first (baseline)**

```
dotnet test tests/AI.Sentinel.Tests
```

Expected: all pass.

**Step 2: Rewrite SentinelChatClient as thin shim**

Replace the entire contents of `SentinelChatClient.cs`:

```csharp
using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;

namespace AI.Sentinel;

public sealed class SentinelChatClient(
    IChatClient innerClient,
    DetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options) : DelegatingChatClient(innerClient)
{
    private readonly SentinelPipeline _sentinel = new(innerClient, pipeline, auditStore, interventionEngine, options);

    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        CancellationToken cancellationToken = default)
    {
        var result = await _sentinel.GetResponseResultAsync(messages, chatOptions, cancellationToken)
            .ConfigureAwait(false);
        return result.Match(ok => ok, err => throw err.ToException());
    }

    public override IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
        => StreamingPassThroughAsync(messages, chatOptions, cancellationToken);

    private async IAsyncEnumerable<ChatResponseUpdate> StreamingPassThroughAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var update in base.GetStreamingResponseAsync(messages, chatOptions, cancellationToken)
            .ConfigureAwait(false))
            yield return update;
    }
}
```

Note: streaming scan is intentionally left as pass-through for now — the Result API for streaming (`IAsyncEnumerable<Result<...>>`) is a follow-on item. The IChatClient shim just proxies the stream.

**Step 3: Run full test suite**

```
dotnet test tests/AI.Sentinel.Tests
```

Expected: all tests pass.

**Step 4: Run build for both projects**

```
dotnet build src/AI.Sentinel
dotnet build src/AI.Sentinel.AspNetCore
```

Expected: both build clean.

**Step 5: Commit**

```bash
git add src/AI.Sentinel/SentinelChatClient.cs
git commit -m "refactor: SentinelChatClient delegates to SentinelPipeline (thin shim)"
```

---

## Task 9: Register SentinelPipeline in DI

**Files:**
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`

**Step 1: Add SentinelPipeline registration**

In `AddAISentinel`, after `InterventionEngine` registration, add:

```csharp
services.AddSingleton(sp => new SentinelPipeline(
    opts.EscalationClient ?? throw new InvalidOperationException("EscalationClient must be set to use SentinelPipeline directly. For IChatClient usage, call UseAISentinel() on ChatClientBuilder."),
    sp.GetRequiredService<DetectionPipeline>(),
    sp.GetRequiredService<IAuditStore>(),
    sp.GetRequiredService<InterventionEngine>(),
    opts));
```

Actually, `SentinelPipeline` needs an `IChatClient` — the inner client is supplied at `UseAISentinel()` time via `ChatClientBuilder`. So `SentinelPipeline` should NOT be registered as a singleton in DI directly — it's constructed by `SentinelChatClient` which receives the inner client.

Instead, skip this step. `SentinelChatClient` already constructs `SentinelPipeline` in its constructor. The `UseAISentinel()` extension already wires `SentinelChatClient` with the inner client.

**Step 1 (revised): Expose SentinelPipeline from UseAISentinel for direct callers**

Add a new extension method on `ChatClientBuilder` that builds `SentinelPipeline` instead of `SentinelChatClient`:

```csharp
public static SentinelPipeline BuildSentinelPipeline(
    this IServiceProvider sp,
    IChatClient innerClient)
{
    return new SentinelPipeline(
        innerClient,
        sp.GetRequiredService<DetectionPipeline>(),
        sp.GetRequiredService<IAuditStore>(),
        sp.GetRequiredService<InterventionEngine>(),
        sp.GetRequiredService<SentinelOptions>());
}
```

Add this to `ServiceCollectionExtensions.cs`.

**Step 2: Write a test for the factory method**

In `tests/AI.Sentinel.Tests/ServiceCollectionExtensionsTests.cs`, add:

```csharp
[Fact]
public void BuildSentinelPipeline_ReturnsInstance()
{
    var services = new ServiceCollection();
    services.AddAISentinel();
    var provider = services.BuildServiceProvider();

    var inner = new TestChatClient();
    var pipeline = provider.BuildSentinelPipeline(inner);
    Assert.NotNull(pipeline);
}

private sealed class TestChatClient : IChatClient
{
    public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
        => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "ok")]));
    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
        => throw new NotImplementedException();
    public ChatClientMetadata Metadata => new("test", null, null);
    public TService? GetService<TService>(object? key = null) where TService : class => null;
    public void Dispose() { }
}
```

**Step 3: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "ServiceCollectionExtensionsTests"
```

Expected: PASS.

**Step 4: Commit**

```bash
git add src/AI.Sentinel/ServiceCollectionExtensions.cs tests/AI.Sentinel.Tests/ServiceCollectionExtensionsTests.cs
git commit -m "feat: expose BuildSentinelPipeline factory for Result-API callers"
```

---

## Task 10: Add optional webhook alert sink

**Files:**
- Modify: `src/AI.Sentinel/SentinelOptions.cs`
- Modify: `src/AI.Sentinel/AI.Sentinel.csproj`
- Create: `src/AI.Sentinel/Alerts/IAlertSink.cs`
- Create: `src/AI.Sentinel/Alerts/NullAlertSink.cs`
- Create: `src/AI.Sentinel/Alerts/WebhookAlertSink.cs`
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`

**Step 1: Add AlertWebhook property to SentinelOptions**

In `SentinelOptions.cs`, add:

```csharp
public Uri? AlertWebhook { get; set; }
```

**Step 2: Create IAlertSink**

```csharp
namespace AI.Sentinel.Alerts;

public interface IAlertSink
{
    ValueTask SendAsync(SentinelError error, CancellationToken ct);
}
```

**Step 3: Create NullAlertSink (no-op default)**

```csharp
namespace AI.Sentinel.Alerts;

public sealed class NullAlertSink : IAlertSink
{
    public static readonly NullAlertSink Instance = new();
    public ValueTask SendAsync(SentinelError error, CancellationToken ct) => ValueTask.CompletedTask;
}
```

**Step 4: Create WebhookAlertSink**

```csharp
using System.Net.Http.Json;
using AI.Sentinel.Alerts;

namespace AI.Sentinel.Alerts;

public sealed class WebhookAlertSink(Uri endpoint) : IAlertSink
{
    private static readonly HttpClient _http = new();

    public async ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        var payload = error switch
        {
            SentinelError.ThreatDetected t => new
            {
                type = "ThreatDetected",
                severity = t.Result.Severity.ToString(),
                detector = t.Result.DetectorId.ToString(),
                reason = t.Result.Reason,
                action = t.Action.ToString()
            },
            SentinelError.PipelineFailure f => new
            {
                type = "PipelineFailure",
                severity = "Unknown",
                detector = "n/a",
                reason = f.Message,
                action = "n/a"
            },
            _ => new { type = "Unknown", severity = "Unknown", detector = "n/a", reason = "", action = "n/a" }
        };

        try
        {
            await _http.PostAsJsonAsync(endpoint, payload, ct).ConfigureAwait(false);
        }
        catch
        {
            // fire-and-forget — never let a webhook failure surface to the caller
        }
    }
}
```

**Step 5: Wire IAlertSink into SentinelPipeline**

In `SentinelPipeline.cs`, add `IAlertSink alertSink` as a constructor parameter with a default:

```csharp
public sealed class SentinelPipeline(
    IChatClient innerClient,
    DetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options,
    IAlertSink? alertSink = null)
```

In `ScanAsync`, after detecting a quarantine error, fire the sink before returning:

```csharp
if (action == SentinelAction.Quarantine || action == SentinelAction.Alert)
{
    var top = pipelineResult.Detections.FirstOrDefault()
        ?? DetectionResult.Clean(new DetectorId("unknown"));
    var sentinelErr = new SentinelError.ThreatDetected(top, action);
    if (_alertSink is not null)
        _ = _alertSink.SendAsync(sentinelErr, ct).AsTask();
    if (action == SentinelAction.Quarantine)
        return sentinelErr;
}
```

Store `alertSink` as `_alertSink` field.

In `BuildSentinelPipeline` factory in `ServiceCollectionExtensions.cs`, wire the sink:

```csharp
var opts = sp.GetRequiredService<SentinelOptions>();
IAlertSink sink = opts.AlertWebhook is not null
    ? new WebhookAlertSink(opts.AlertWebhook)
    : NullAlertSink.Instance;
return new SentinelPipeline(innerClient, ..., sink);
```

**Step 6: Write a test**

In `tests/AI.Sentinel.Tests/Alerts/WebhookAlertSinkTests.cs`:

```csharp
using AI.Sentinel.Alerts;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Alerts;

public class AlertSinkTests
{
    [Fact]
    public async Task NullAlertSink_DoesNotThrow()
    {
        var error = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test"),
            SentinelAction.Quarantine);
        await NullAlertSink.Instance.SendAsync(error, default);
        // no assertion needed — just confirms no throw
    }
}
```

**Step 7: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "AlertSinkTests"
```

Expected: PASS.

**Step 8: Run full suite**

```
dotnet test tests/AI.Sentinel.Tests
```

Expected: all pass.

**Step 9: Commit**

```bash
git add src/AI.Sentinel/Alerts/ src/AI.Sentinel/SentinelOptions.cs src/AI.Sentinel/SentinelPipeline.cs src/AI.Sentinel/ServiceCollectionExtensions.cs tests/AI.Sentinel.Tests/Alerts/
git commit -m "feat: add optional webhook alert sink (IAlertSink / WebhookAlertSink)"
```

---

## Task 11: Final integration smoke test + full suite

**Step 1: Run the complete test suite**

```
dotnet test
```

Expected: all tests pass across all test projects.

**Step 2: Build release configuration**

```
dotnet build -c Release
```

Expected: no errors, no warnings about MA0051.

**Step 3: Commit if any stray changes remain**

```bash
git status
# if nothing: done
git add -u && git commit -m "chore: final cleanup after ZeroAlloc native integration"
```

---

## Summary of Changes

| Area | Before | After |
|------|--------|-------|
| Detector registration | 43 explicit `AddSingleton` calls | `[Singleton]` attributes + `AddAISentinelDetectors()` |
| Error model | `throw SentinelException` | `Result<ChatResponse, SentinelError>` |
| Primary API | `SentinelChatClient` (throws) | `SentinelPipeline.GetResponseResultAsync()` |
| IChatClient compat | Primary surface | Thin shim in `SentinelChatClient` |
| Webhook alerts | Not supported | Optional `SentinelOptions.AlertWebhook` |
