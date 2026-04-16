# Performance Optimisation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce per-call heap allocations on the clean path from ~16 KB to ~2.8 KB per `SentinelChatClient.GetResponseAsync` call (~80% reduction) without changing any public API.

**Architecture:** Four targeted changes: (1) cache joined message text on `SentinelContext` to eliminate redundant string allocations across detectors; (2) cache `DetectorId` and `DetectionResult.Clean` as static fields in every detector; (3) add a sync fast-path in `DetectionPipeline` that skips `Task.WhenAll` when all detectors complete synchronously; (4) rewrite `RepetitionLoopDetector` with a span-based single-pass algorithm. No public API changes.

**Tech Stack:** .NET 9, C# 13, `System.Buffers.ArrayPool<T>`, `MemoryExtensions.Split` (span-based), BenchmarkDotNet for verification.

---

## Task 1: SentinelContext — convert to class with lazy TextContent cache

**Files:**
- Modify: `src/AI.Sentinel/Detection/SentinelContext.cs`

Nine detectors currently call `string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""))` independently on the same context. This task adds a lazy-cached `TextContent` property so the string is built once per context regardless of how many detectors read it.

`SentinelContext` must change from `sealed record` to `sealed class` to support a mutable backing field. The public constructor signature stays identical, so all call sites (tests, `SentinelChatClient`, `DetectionPipeline`) compile unchanged.

**Step 1: Verify all existing tests pass as baseline**

```
dotnet test tests/AI.Sentinel.Tests --no-build -c Release 2>&1 | tail -5
```
Expected: all passing.

**Step 2: Rewrite SentinelContext.cs**

```csharp
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public sealed class SentinelContext(
    AgentId SenderId,
    AgentId ReceiverId,
    SessionId SessionId,
    IReadOnlyList<ChatMessage> Messages,
    IReadOnlyList<AuditEntry> History,
    string? LlmId = null)
{
    public AgentId   SenderId   { get; } = SenderId;
    public AgentId   ReceiverId { get; } = ReceiverId;
    public SessionId SessionId  { get; } = SessionId;
    public IReadOnlyList<ChatMessage> Messages { get; } = Messages;
    public IReadOnlyList<AuditEntry>  History  { get; } = History;
    public string? LlmId { get; } = LlmId;

    private string? _textContent;

    /// <summary>
    /// All message texts joined with a single space.
    /// Computed once and cached — use this instead of string.Join in detector implementations.
    /// </summary>
    public string TextContent =>
        _textContent ??= string.Join(" ", Messages.Select(m => m.Text ?? ""));
}
```

**Step 3: Build and run tests**

```
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release
dotnet test tests/AI.Sentinel.Tests -c Release 2>&1 | tail -5
```
Expected: build succeeds, all tests pass. (The record → class change is source-compatible for all positional-constructor uses.)

**Step 4: Commit**

```
git add src/AI.Sentinel/Detection/SentinelContext.cs
git commit -m "perf: convert SentinelContext to class with lazy TextContent cache"
```

---

## Task 2: StubDetector base class — static DetectorId + cached clean result

**Files:**
- Modify: `src/AI.Sentinel/Detectors/StubDetector.cs`

`StubDetector` is the base class for 18 LLM-escalation-only detectors. It currently allocates a new `DetectorId` on every `Id` access and a new `DetectionResult.Clean` on every `AnalyzeAsync` call. Fixing the base class fixes all 18 subclasses for free.

**Step 1: Rewrite StubDetector.cs**

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detectors;

/// <summary>Base for detectors whose full rule-based implementation requires LLM escalation.</summary>
public abstract class StubDetector : ILlmEscalatingDetector
{
    private readonly DetectorId _id;
    private readonly DetectionResult _clean;

    protected StubDetector(string id, DetectorCategory category)
    {
        _id      = new DetectorId(id);
        _clean   = DetectionResult.Clean(_id);
        Category = category;
    }

    public DetectorId       Id       => _id;
    public DetectorCategory Category { get; }

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
        ValueTask.FromResult(_clean);
}
```

Note: `_id` and `_clean` are instance fields here (not static) because each subclass has a different ID string passed via the constructor. They are effectively static in practice since `StubDetector` subclasses are registered as singletons in DI.

**Step 2: Build and run tests**

```
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release
dotnet test tests/AI.Sentinel.Tests -c Release 2>&1 | tail -5
```
Expected: all tests pass.

**Step 3: Commit**

```
git add src/AI.Sentinel/Detectors/StubDetector.cs
git commit -m "perf: cache DetectorId and clean DetectionResult in StubDetector"
```

---

## Task 3: 8 regex detectors — static cache + ctx.TextContent

**Files to modify (8 files):**
- `src/AI.Sentinel/Detectors/Security/PromptInjectionDetector.cs`
- `src/AI.Sentinel/Detectors/Security/JailbreakDetector.cs`
- `src/AI.Sentinel/Detectors/Security/CredentialExposureDetector.cs`
- `src/AI.Sentinel/Detectors/Security/DataExfiltrationDetector.cs`
- `src/AI.Sentinel/Detectors/Security/PrivilegeEscalationDetector.cs`
- `src/AI.Sentinel/Detectors/Hallucination/PhantomCitationDetector.cs`
- `src/AI.Sentinel/Detectors/Hallucination/SelfConsistencyDetector.cs`
- `src/AI.Sentinel/Detectors/Operational/PlaceholderTextDetector.cs`

All 8 currently do `string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""))` and return `DetectionResult.Clean(Id)` on the clean path. Apply three changes to each:
1. Add `private static readonly DetectorId _id = new("XYZ");`
2. Add `private static readonly DetectionResult _clean = DetectionResult.Clean(_id);`
3. Change `public DetectorId Id => new("XYZ");` to `public DetectorId Id => _id;`
4. Replace `string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""))` with `ctx.TextContent`
5. Replace `DetectionResult.Clean(Id)` with `_clean` on clean-path returns

**The pattern to apply (shown once for PromptInjectionDetector, apply identically to all 8):**

```csharp
// src/AI.Sentinel/Detectors/Security/PromptInjectionDetector.cs
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class PromptInjectionDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-01");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|" +
        @"forget\s+(your\s+)?(previous|prior|all)\s+instructions?|" +
        @"you\s+are\s+now\s+a\s+different|" +
        @"SYSTEM\s*:\s*(you\s+are|ignore)|" +
        @"new\s+persona|pretend\s+you\s+are|act\s+as\s+if|" +
        @"disregard\s+(all\s+)?previous)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex InjectionPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var match = InjectionPattern().Match(ctx.TextContent);
        if (!match.Success) return ValueTask.FromResult(_clean);
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Critical,
            $"Prompt injection pattern: '{match.Value}'"));
    }
}
```

**ID mapping for the other 7 detectors** (keep their existing `[GeneratedRegex]` and regex pattern unchanged — only change `Id`, `_id`, `_clean`, and `ctx.TextContent`):

| File | Detector class | ID string | Severity on hit |
|---|---|---|---|
| JailbreakDetector.cs | `JailbreakDetector` | `"SEC-13"` | `Severity.Critical` |
| CredentialExposureDetector.cs | `CredentialExposureDetector` | `"SEC-02"` | `Severity.Critical` |
| DataExfiltrationDetector.cs | `DataExfiltrationDetector` | `"SEC-04"` | (keep existing) |
| PrivilegeEscalationDetector.cs | `PrivilegeEscalationDetector` | `"SEC-06"` | (keep existing) |
| PhantomCitationDetector.cs | `PhantomCitationDetector` | `"HAL-01"` | `Severity.Medium` |
| SelfConsistencyDetector.cs | `SelfConsistencyDetector` | `"HAL-05"` | `Severity.Low` |
| PlaceholderTextDetector.cs | `PlaceholderTextDetector` | `"OPS-07"` | `Severity.Low` |

> **Tip:** For each file, do a find-replace: `string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""))` → `ctx.TextContent`, `DetectionResult.Clean(Id)` → `_clean`, and add the two static fields. The `[GeneratedRegex]` attribute and regex string do not change.

**Step 1: Apply changes to all 8 files using the pattern above**

**Step 2: Build**

```
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release
```
Expected: 0 errors, 0 warnings.

**Step 3: Run tests**

```
dotnet test tests/AI.Sentinel.Tests -c Release 2>&1 | tail -5
```
Expected: all tests pass.

**Step 4: Commit**

```
git add src/AI.Sentinel/Detectors/Security/PromptInjectionDetector.cs \
        src/AI.Sentinel/Detectors/Security/JailbreakDetector.cs \
        src/AI.Sentinel/Detectors/Security/CredentialExposureDetector.cs \
        src/AI.Sentinel/Detectors/Security/DataExfiltrationDetector.cs \
        src/AI.Sentinel/Detectors/Security/PrivilegeEscalationDetector.cs \
        src/AI.Sentinel/Detectors/Hallucination/PhantomCitationDetector.cs \
        src/AI.Sentinel/Detectors/Hallucination/SelfConsistencyDetector.cs \
        src/AI.Sentinel/Detectors/Operational/PlaceholderTextDetector.cs
git commit -m "perf: add static DetectorId/clean cache and use ctx.TextContent in 8 regex detectors"
```

---

## Task 4: BlankResponseDetector + IncompleteCodeBlockDetector — static cache only

**Files:**
- Modify: `src/AI.Sentinel/Detectors/Operational/BlankResponseDetector.cs`
- Modify: `src/AI.Sentinel/Detectors/Operational/IncompleteCodeBlockDetector.cs`

These two detectors do NOT use `string.Join(" ", ...)` — they use `""` and `"\n"` separators respectively, which are semantically different from `TextContent`. Apply only the static `_id` and `_clean` fields.

**BlankResponseDetector.cs:**

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed class BlankResponseDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-01");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join("", ctx.Messages.Select(m => m.Text ?? "")).Trim();
        if (text.Length == 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium, "Blank or whitespace-only response"));
        if (text.Length < 10)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low, "Suspiciously short response"));
        return ValueTask.FromResult(_clean);
    }
}
```

**IncompleteCodeBlockDetector.cs:**

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed class IncompleteCodeBlockDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-06");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join("\n", ctx.Messages.Select(m => m.Text ?? ""));
        var opens = text.Split("```").Length - 1;
        if (opens % 2 != 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                "Unclosed code block — response may be truncated"));
        return ValueTask.FromResult(_clean);
    }
}
```

**Step 1: Apply both changes**

**Step 2: Build and run tests**

```
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release
dotnet test tests/AI.Sentinel.Tests -c Release 2>&1 | tail -5
```
Expected: all tests pass.

**Step 3: Commit**

```
git add src/AI.Sentinel/Detectors/Operational/BlankResponseDetector.cs \
        src/AI.Sentinel/Detectors/Operational/IncompleteCodeBlockDetector.cs
git commit -m "perf: add static DetectorId/clean cache to BlankResponse and IncompleteCodeBlock detectors"
```

---

## Task 5: DetectionPipeline — sync fast-path + ArrayPool + remove LINQ aggregation

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`

This is the highest-impact single change. Replace the LINQ + `Task.WhenAll` path with:
1. A pooled `ValueTask<DetectionResult>[]` buffer (eliminates the LINQ iterator allocation)
2. A sync fast-path that checks `IsCompletedSuccessfully` on all ValueTasks before touching `Task.WhenAll` (eliminates ~3,000 B of `Task<DetectionResult>` boxing on the clean path)
3. Plain loops instead of `Where(...).ToList()` and `Select(...)` in result aggregation

The LLM escalation logic is preserved unchanged.

**Step 1: Rewrite DetectionPipeline.cs**

```csharp
using System.Buffers;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Detection;

public sealed class DetectionPipeline
{
    private readonly IDetector[] _detectors;
    private readonly IChatClient? _escalationClient;
    private readonly ILogger<DetectionPipeline>? _logger;

    public DetectionPipeline(
        IEnumerable<IDetector> detectors,
        IChatClient? escalationClient,
        ILogger<DetectionPipeline>? logger = null)
    {
        _detectors       = detectors.ToArray();
        _escalationClient = escalationClient;
        _logger          = logger;
    }

    private static int SeverityScore(Severity s) => s switch
    {
        Severity.Critical => 100,
        Severity.High     => 70,
        Severity.Medium   => 40,
        Severity.Low      => 15,
        _                 => 0
    };

    public async ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct)
    {
        if (_detectors.Length == 0)
            return new PipelineResult(ThreatRiskScore.Zero, []);

        var vTasks = ArrayPool<ValueTask<DetectionResult>>.Shared.Rent(_detectors.Length);
        DetectionResult[] results;
        try
        {
            // Start all detectors
            for (int i = 0; i < _detectors.Length; i++)
                vTasks[i] = _detectors[i].AnalyzeAsync(ctx, ct);

            // Fast path: all synchronous (typical for rule-based detectors with cached clean results)
            if (AllCompletedSuccessfully(vTasks, _detectors.Length))
            {
                results = new DetectionResult[_detectors.Length];
                for (int i = 0; i < _detectors.Length; i++)
                    results[i] = vTasks[i].Result;
            }
            else
            {
                // Slow path: at least one async detector — use Task.WhenAll
                var tasks = new Task<DetectionResult>[_detectors.Length];
                for (int i = 0; i < _detectors.Length; i++)
                    tasks[i] = vTasks[i].AsTask();
                results = await Task.WhenAll(tasks).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<ValueTask<DetectionResult>>.Shared.Return(vTasks);
        }

        // LLM escalation (unchanged logic)
        if (_escalationClient is not null)
        {
            var escalated = new List<DetectionResult>(results.Length);
            for (int i = 0; i < _detectors.Length; i++)
            {
                var r = results[i];
                if (r.Severity >= Severity.Medium && _detectors[i] is ILlmEscalatingDetector)
                {
                    var upgraded = await EscalateAsync(_detectors[i], ctx, r, _escalationClient, _logger, ct).ConfigureAwait(false);
                    escalated.Add(upgraded);
                }
                else escalated.Add(r);
            }
            results = escalated.ToArray();
        }

        return BuildResult(results);
    }

    private static bool AllCompletedSuccessfully(ValueTask<DetectionResult>[] tasks, int count)
    {
        for (int i = 0; i < count; i++)
            if (!tasks[i].IsCompletedSuccessfully) return false;
        return true;
    }

    private static PipelineResult BuildResult(DetectionResult[] results)
    {
        var nonClean = new List<DetectionResult>();
        var scores   = new ThreatRiskScore[results.Length];
        for (int i = 0; i < results.Length; i++)
        {
            if (!results[i].IsClean) nonClean.Add(results[i]);
            scores[i] = new ThreatRiskScore(SeverityScore(results[i].Severity));
        }
        var score = ThreatRiskScore.Aggregate(scores);
        return new PipelineResult(score, nonClean);
    }

    private static async ValueTask<DetectionResult> EscalateAsync(
        IDetector detector,
        SentinelContext ctx,
        DetectionResult initial,
        IChatClient client,
        ILogger<DetectionPipeline>? logger,
        CancellationToken ct)
    {
        var instruction = new ChatMessage(ChatRole.System,
            $$"""
            You are a security classifier. A rule-based detector (rule ID: {{detector.Id}}) flagged incoming content at severity {{initial.Severity}}.
            Your task: assess whether the content justifies {{initial.Severity}} severity or should be lower.
            Respond with JSON only, no explanation: {"severity":"None|Low|Medium|High|Critical","reason":"one sentence"}
            """);

        var contentMessage = new ChatMessage(ChatRole.User,
            ctx.Messages.LastOrDefault()?.Text ?? "(empty)");

        try
        {
            var response = await client.GetResponseAsync(
                new List<ChatMessage> { instruction, contentMessage },
                cancellationToken: ct).ConfigureAwait(false);

            var text = response.Text ?? "";
            if (text.Contains("\"Critical\"", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("Critical", StringComparison.Ordinal))
                return DetectionResult.WithSeverity(detector.Id, Severity.Critical, "LLM escalated to Critical");
            if (text.Contains("\"High\"", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.High, "LLM escalated to High");
            if (text.Contains("\"Medium\"", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.Medium, "LLM escalated to Medium");
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "LLM escalation failed for detector {DetectorId}", detector.Id);
        }

        return initial;
    }
}
```

**Step 2: Build and run all tests**

```
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release
dotnet test tests/AI.Sentinel.Tests -c Release
```
Expected: 0 errors, all tests pass. The `DetectionPipelineTests` verify correctness of parallel execution, escalation, and result aggregation.

**Step 3: Commit**

```
git add src/AI.Sentinel/Detection/DetectionPipeline.cs
git commit -m "perf: sync fast-path and ArrayPool in DetectionPipeline, remove LINQ aggregation"
```

---

## Task 6: RepetitionLoopDetector — span-based single-pass rewrite

**Files:**
- Modify: `src/AI.Sentinel/Detectors/Operational/RepetitionLoopDetector.cs`

Current implementation: `Split → Select(ToLowerInvariant) → ToList → GroupBy`. Measured at 453 ns / 912 B for a clean short input.

Replacement: span-based split with `OrdinalIgnoreCase` dictionary, single pass, no intermediate array or list.

**Step 1: Verify existing RepetitionLoop test**

The test in `tests/AI.Sentinel.Tests/Detectors/Operational/OperationalDetectorTests.cs` checks:
```csharp
[Fact] public async Task RepetitionLoop_Detected()
{
    var repeated = string.Join(". ", Enumerable.Repeat("I cannot help with that", 5));
    Assert.True((await new RepetitionLoopDetector().AnalyzeAsync(Ctx(repeated), default)).Severity >= Severity.Medium);
}
```
This must still pass after the rewrite.

**Step 2: Rewrite RepetitionLoopDetector.cs**

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Operational;

public sealed class RepetitionLoopDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-02");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int maxRepeat = 0;

        foreach (var range in text.AsSpan().Split(['.', '!', '?']))
        {
            var sentence = text[range].Trim();
            if (sentence.Length <= 5) continue;

            var count = counts.TryGetValue(sentence, out var c) ? c + 1 : 1;
            counts[sentence] = count;
            if (count > maxRepeat) maxRepeat = count;
        }

        if (maxRepeat >= 3)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Sentence repeated {maxRepeat}x — possible repetition loop"));
        return ValueTask.FromResult(_clean);
    }
}
```

Key changes vs. original:
- `text.AsSpan().Split(...)` — `SpanSplitEnumerator`, no array allocation for the sentence split
- `StringComparer.OrdinalIgnoreCase` on dictionary replaces `.ToLowerInvariant()` per sentence
- Single pass — no `ToList()`, no `GroupBy()`
- Uses `ctx.TextContent` (from Task 1)

**Step 3: Run tests**

```
dotnet build src/AI.Sentinel/AI.Sentinel.csproj -c Release
dotnet test tests/AI.Sentinel.Tests -c Release 2>&1 | tail -5
```
Expected: all tests pass including `RepetitionLoop_Detected` and `CleanResponse_NoFlags`.

**Step 4: Commit**

```
git add src/AI.Sentinel/Detectors/Operational/RepetitionLoopDetector.cs
git commit -m "perf: rewrite RepetitionLoopDetector with span-based single-pass algorithm"
```

---

## Task 7: Verify with benchmarks

**Purpose:** Confirm the projected allocation reduction materialises in practice.

**Step 1: Run the benchmark suite (short job, fast)**

```
dotnet run --project benchmarks/AI.Sentinel.Benchmarks -c Release -- --job short --filter "*" 2>&1 | grep -E "^\|"
```

**Step 2: Check the key numbers against targets**

| Benchmark | Baseline | Target |
|---|---|---|
| Pipeline — all-30 / clean | 7,864 B | < 2,000 B |
| E2E — clean short / all | 16,048 B | < 4,000 B |
| Detector — RepetitionLoop / clean | 912 B | < 200 B |
| Detector — PromptInjection / clean | 152 B | < 32 B |

If any benchmark regresses (e.g. more allocated than baseline), check the corresponding task. Common causes:
- Static field not added → `DetectorId` still allocates per call
- `ctx.TextContent` not used → `string.Join` still called per detector
- Fast-path not taken → check that `IsCompletedSuccessfully` is `true` for all sync detectors (it will be after the cached `_clean` fix since `ValueTask.FromResult` always completes synchronously)

**Step 3: Update README benchmarks table**

In `README.md`, update the Benchmarks section with the new numbers from the run.

**Step 4: Commit**

```
git add README.md
git commit -m "docs: update benchmark numbers after performance optimisation"
```
