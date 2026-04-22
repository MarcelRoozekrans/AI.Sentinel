# Output Schema Validation (SEC-29) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `OutputSchemaDetector` (SEC-29) that validates LLM responses against a caller-supplied expected type using `ZeroAlloc.Serialisation`.

**Architecture:** New detector in the Security category. Activates when `SentinelOptions.ExpectedResponseType` is set. Extracts the last assistant message, unwraps markdown code fences, and attempts to deserialize via `ISerializerDispatcher`. Deserialization failure → `Severity.High`.

**Tech Stack:** `ZeroAlloc.Serialisation 1.3.*` (source-generated serializers + dispatcher), `[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]` annotation on caller types, `ZeroAlloc.Inject` for DI registration.

---

## Context: key facts

- All existing Security detectors live in `src/AI.Sentinel/Detectors/Security/` and follow the pattern: `[Singleton(As = typeof(IDetector), AllowMultiple = true)]`, static `DetectorId`/`_clean` fields, `DetectorCategory.Security`.
- Existing detector count: 44 (Security 24, Hallucination 8, Operational 12). Adding SEC-29 brings it to 45 (Security 25).
- DI registration is automatic via ZeroAlloc.Inject source generator — no changes to `ServiceCollectionExtensions` needed.
- `ISerializerDispatcher` is injected. Callers register it via `services.AddSerializerDispatcher()` (source-generated extension per assembly that has `[ZeroAllocSerializable]` types).
- For AI.Sentinel's own assembly: no `[ZeroAllocSerializable]` types → no dispatcher emitted. The detector just takes `ISerializerDispatcher` as a constructor parameter.
- For the test project: we add one `[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]` test POCO → generator emits a `SerializerDispatcher` class we can instantiate directly in unit tests.

**Test runner:**
```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

---

## Task 1: Add package reference + `ExpectedResponseType` option

**Files:**
- Modify: `src/AI.Sentinel/AI.Sentinel.csproj`
- Modify: `src/AI.Sentinel/SentinelOptions.cs`
- Modify: `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs`

### Step 1: Write the failing test

Append to `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs` (inside the class):

```csharp
[Fact]
public void ExpectedResponseType_DefaultsToNull()
{
    var opts = new SentinelOptions();
    Assert.Null(opts.ExpectedResponseType);
}
```

### Step 2: Run to verify failure

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "ExpectedResponseType_DefaultsToNull" 2>&1 | tail -10
```

Expected: build error — `ExpectedResponseType` does not exist.

### Step 3: Add the package reference

In `src/AI.Sentinel/AI.Sentinel.csproj`, add inside the `<ItemGroup>` containing the other `ZeroAlloc.*` references (after `ZeroAlloc.Resilience`):

```xml
<PackageReference Include="ZeroAlloc.Serialisation" Version="1.3.*" />
```

### Step 4: Add the `ExpectedResponseType` property

In `src/AI.Sentinel/SentinelOptions.cs`, add after the `SessionIdleTimeout` property:

```csharp
    /// <summary>Optional expected response type for structured-output LLM calls.
    /// When set, <c>OutputSchemaDetector</c> (SEC-29) attempts to deserialize each assistant
    /// response as this type via the registered <c>ISerializerDispatcher</c>.
    /// The type must be annotated with <c>[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]</c>.
    /// <c>null</c> (default) disables the detector.</summary>
    public Type? ExpectedResponseType { get; set; }
```

### Step 5: Build and verify

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -5
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: 0 errors, new test passes, all existing tests pass.

### Step 6: Commit

```bash
git add src/AI.Sentinel/AI.Sentinel.csproj src/AI.Sentinel/SentinelOptions.cs tests/AI.Sentinel.Tests/SentinelOptionsTests.cs
git commit -m "feat: add ExpectedResponseType option + ZeroAlloc.Serialisation dep"
```

---

## Task 2: Create `OutputSchemaDetector` + unit tests

**Files:**
- Modify: `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj` — add `ZeroAlloc.Serialisation.SystemTextJson` + generator
- Create: `tests/AI.Sentinel.Tests/Detectors/Security/OutputSchemaDetectorTests.cs`
- Create: `src/AI.Sentinel/Detectors/Security/OutputSchemaDetector.cs`

### Step 1: Update test project packages

In `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj`, add inside the `<ItemGroup>` (after the `NSubstitute` line):

```xml
<PackageReference Include="ZeroAlloc.Serialisation" Version="1.3.*" />
<PackageReference Include="ZeroAlloc.Serialisation.SystemTextJson" Version="1.3.*" />
<PackageReference Include="ZeroAlloc.Serialisation.Generator" Version="1.3.*" OutputItemType="Analyzer" ReferenceOutputAssembly="false" />
```

### Step 2: Write the failing tests

Create `tests/AI.Sentinel.Tests/Detectors/Security/OutputSchemaDetectorTests.cs`:

```csharp
using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Detectors.Security;
using ZeroAlloc.Serialisation;

namespace AI.Sentinel.Tests.Detectors.Security;

[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]
public sealed record WeatherResponse(string City, double TemperatureC);

public class OutputSchemaDetectorTests
{
    private static SentinelContext Ctx(params ChatMessage[] msgs) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        msgs.ToList(),
        new List<AuditEntry>());

    private static OutputSchemaDetector Build(SentinelOptions opts) =>
        new(opts, new SerializerDispatcher());

    [Fact]
    public async Task ExpectedTypeNotSet_ReturnsClean()
    {
        var d = Build(new SentinelOptions());
        var r = await d.AnalyzeAsync(Ctx(new ChatMessage(ChatRole.Assistant, "anything")), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task NoAssistantMessage_ReturnsClean()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(Ctx(new ChatMessage(ChatRole.User, "hi")), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task ValidJson_MatchesType_ReturnsClean()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, """{"city":"Amsterdam","temperatureC":12}""")),
            default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task MalformedJson_ReturnsHigh()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, "{not valid json")),
            default);
        Assert.Equal(Severity.High, r.Severity);
    }

    [Fact]
    public async Task MissingRequiredProperty_ReturnsHigh()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        // Missing "TemperatureC" — WeatherResponse record has no default for it
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, """{"city":"Amsterdam"}""")),
            default);
        Assert.Equal(Severity.High, r.Severity);
    }

    [Fact]
    public async Task WrappedInCodeFence_IsExtracted()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var fenced = "```json\n{\"city\":\"NYC\",\"temperatureC\":5}\n```";
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, fenced)),
            default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task NullDeserialization_ReturnsHigh()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, "null")),
            default);
        Assert.Equal(Severity.High, r.Severity);
    }
}
```

**Note:** `SerializerDispatcher` is emitted by the ZeroAlloc.Serialisation source generator in the test assembly's root namespace. It's available because we annotated `WeatherResponse` with `[ZeroAllocSerializable]`.

### Step 3: Run to verify tests fail

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "OutputSchemaDetectorTests" 2>&1 | tail -15
```

Expected: build error — `OutputSchemaDetector` does not exist.

### Step 4: Implement the detector

Create `src/AI.Sentinel/Detectors/Security/OutputSchemaDetector.cs`:

```csharp
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
using ZeroAlloc.Serialisation;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class OutputSchemaDetector(
    SentinelOptions options,
    ISerializerDispatcher dispatcher) : IDetector
{
    private static readonly DetectorId _id = new("SEC-29");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        if (options.ExpectedResponseType is not Type expected)
            return ValueTask.FromResult(_clean);

        string? responseText = null;
        for (var i = ctx.Messages.Count - 1; i >= 0; i--)
        {
            if (ctx.Messages[i].Role == ChatRole.Assistant && ctx.Messages[i].Text is { Length: > 0 } t)
            {
                responseText = t;
                break;
            }
        }
        if (responseText is null) return ValueTask.FromResult(_clean);

        var jsonText = ExtractJson(responseText);
        var bytes = Encoding.UTF8.GetBytes(jsonText);

        try
        {
            var deserialized = dispatcher.Deserialize(bytes, expected);
            if (deserialized is null)
                return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                    $"Response deserialized to null for type {expected.Name}"));
            return ValueTask.FromResult(_clean);
        }
        catch (JsonException ex)
        {
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"Response failed schema validation for {expected.Name}: {ex.Message}"));
        }
        catch (NotSupportedException)
        {
            // Type not registered with the dispatcher — caller misconfiguration, not a threat.
            return ValueTask.FromResult(_clean);
        }
    }

    private static string ExtractJson(string text)
    {
        var trimmed = text.AsSpan().Trim();
        if (!trimmed.StartsWith("```")) return text;

        var afterFence = trimmed[3..];
        var newline = afterFence.IndexOf('\n');
        if (newline < 0) return text;

        var body = afterFence[(newline + 1)..];
        var closing = body.LastIndexOf("```", StringComparison.Ordinal);
        return closing < 0 ? text : body[..closing].ToString();
    }
}
```

### Step 5: Build and run tests

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release 2>&1 | tail -5
dotnet test tests/AI.Sentinel.Tests -v m --filter "OutputSchemaDetectorTests" 2>&1 | tail -20
```

Expected: all 7 tests pass.

### Step 6: Run full test suite

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: all tests pass (no regressions).

### Step 7: Commit

```bash
git add src/AI.Sentinel/Detectors/Security/OutputSchemaDetector.cs tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj tests/AI.Sentinel.Tests/Detectors/Security/OutputSchemaDetectorTests.cs
git commit -m "feat: add OutputSchemaDetector (SEC-29)"
```

---

## Task 3: End-to-end integration test in `SentinelPipelineTests`

Verify the detector plugs correctly into the full pipeline: prompt scan clean, response scan fails schema, intervention engine returns `ThreatDetected`.

**Files:**
- Modify: `tests/AI.Sentinel.Tests/SentinelPipelineTests.cs`

### Step 1: Write the failing test

Append to the `SentinelPipelineTests` class:

```csharp
[Fact]
public async Task ExpectedType_Configured_ThroughPipeline_ReturnsThreatDetected()
{
    // Inner client returns JSON that's missing the required TemperatureC field
    var inner = new TestChatClient("""{"city":"Amsterdam"}""");

    var opts = new SentinelOptions
    {
        ExpectedResponseType = typeof(AI.Sentinel.Tests.Detectors.Security.WeatherResponse),
        OnCritical = SentinelAction.Alert,
        OnHigh = SentinelAction.Alert
    };

    var detector = new AI.Sentinel.Detectors.Security.OutputSchemaDetector(
        opts, new SerializerDispatcher());
    var pipeline = new DetectionPipeline([detector], null);
    var audit = new RingBufferAuditStore(100);
    var engine = new InterventionEngine(opts, null);
    var sentinel = new SentinelPipeline(inner, pipeline, audit, engine, opts);

    var result = await sentinel.GetResponseResultAsync(
        [new ChatMessage(ChatRole.User, "What's the weather?")],
        null,
        default);

    Assert.True(result.IsFailure);
    Assert.IsType<SentinelError.ThreatDetected>(result.Error);
    var threat = (SentinelError.ThreatDetected)result.Error;
    Assert.Equal(new DetectorId("SEC-29"), threat.Result.DetectorId);
}
```

Ensure the file has these usings (add any missing):
```csharp
using ZeroAlloc.Serialisation;
```

### Step 2: Run to verify the test flow

```bash
dotnet test tests/AI.Sentinel.Tests --no-build -v m --filter "ExpectedType_Configured_ThroughPipeline" 2>&1 | tail -15
```

Expected: test passes (the detector logic from Task 2 already works; this is just verifying the integration path).

If it fails, investigate — likely a DI or options-passing issue.

### Step 3: Run full test suite

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

Expected: all tests pass.

### Step 4: Commit

```bash
git add tests/AI.Sentinel.Tests/SentinelPipelineTests.cs
git commit -m "test: integration test for OutputSchemaDetector through pipeline"
```

---

## Task 4: Update README and BACKLOG

**Files:**
- Modify: `README.md`
- Modify: `docs/BACKLOG.md`

### Step 1: Update README counts

In `README.md`, update three references:

- Line 3 (`scans every prompt and response through 44 detectors`) → `45 detectors`
- Line 25 (Packages table, `Core — pipeline, 44 detectors`) → `45 detectors`
- Line 101 (`## Detectors (44)`) → `## Detectors (45)`

### Step 2: Add SEC-29 to the Security table

Find the Security section header `### Security (24)` — change to `### Security (25)`.

After the last security row (`SEC-28 | RefusalBypass | ...`), add:

```
| SEC-29 | OutputSchema | Rule-based | Response doesn't deserialize as the caller-supplied `ExpectedResponseType` (OWASP LLM05) |
```

### Step 3: Mention `ExpectedResponseType` in Configuration section

Find the Configuration code block in the README (after the `opts.MaxCallsPerSecond` / `opts.BurstSize` lines). Add:

```csharp
    // Optional: validate structured LLM responses against a caller-supplied type.
    // The type must be annotated with [ZeroAllocSerializable(SerializationFormat.SystemTextJson)].
    // Requires calling services.AddSerializerDispatcher() (from ZeroAlloc.Serialisation).
    opts.ExpectedResponseType = typeof(MyResponse);
```

### Step 4: Remove "Output schema validation" from BACKLOG

In `docs/BACKLOG.md`, remove the row:

```
| **Output schema validation** | Validate structured (JSON/XML) responses against a caller-supplied schema before returning to the application — catches malformed outputs and prompt-injected schema violations (cf. OWASP LLM05) |
```

### Step 5: Verify test suite still passes

```bash
dotnet test tests/AI.Sentinel.Tests -v m 2>&1 | tail -20
```

### Step 6: Commit

```bash
git add README.md docs/BACKLOG.md
git commit -m "docs: add SEC-29 OutputSchema detector to README, update BACKLOG"
```
