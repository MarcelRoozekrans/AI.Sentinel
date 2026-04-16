# Performance Optimisation Design — Approach B

## Goal

Reduce per-call allocations on the clean path from ~16 KB to ~2–3 KB per `SentinelChatClient.GetResponseAsync` call (80% reduction) without changing any public API surface.

## Baseline measurements (2026-04-16, .NET 9, Release, Job.Default)

| Benchmark | Mean | Allocated |
|---|---|---|
| Pipeline — empty / clean | 122 ns | 232 B |
| Pipeline — security-only / clean | 1,523 ns | 2,728 B |
| Pipeline — all-30 / clean | 4,325 ns | 7,864 B |
| Pipeline — all-30 / malicious | 8,653 ns | 10,616 B |
| E2E — clean short / all-30 | 15,230 ns | 16,048 B |
| E2E — clean long (10 turns) / all-30 | 50,368 ns | 52,299 B |
| Detector — PromptInjection / clean | 93 ns | 152 B |
| Detector — RepetitionLoop / clean | 453 ns | 912 B |
| AuditStore — sequential append | 54 ns | 0 B |

## Root cause breakdown (7,864 B per pipeline pass, 30 detectors, clean input)

| Source | Approx. cost | File(s) |
|---|---|---|
| `Task<DetectionResult>` boxing via `.AsTask()` | ~3,000 B | `DetectionPipeline.cs` |
| `DetectionResult.Clean` record per call | ~1,440 B | all 30 detector files |
| `DetectorId` heap allocation per `Id` access | ~1,200 B | all 30 detector files |
| `string.Join` + LINQ iterator (9 detectors) | ~900 B | 9 regex detector files |
| Pipeline framework baseline | 232 B | `DetectionPipeline.cs` |

E2E cost ≈ 2× pipeline (prompt pass + response pass) + small overhead for `SessionId`, `SentinelContext`.

## Four changes (all non-breaking)

### Change 1 — `SentinelContext`: lazy `TextContent` cache

**File:** `src/AI.Sentinel/Detection/SentinelContext.cs`

Convert from positional `sealed record` to `sealed class` with identical constructor signature. Add a lazy-initialised `TextContent` property:

```csharp
public sealed class SentinelContext(
    AgentId SenderId, AgentId ReceiverId, SessionId SessionId,
    IReadOnlyList<ChatMessage> Messages, IReadOnlyList<AuditEntry> History,
    string? LlmId = null)
{
    public AgentId SenderId   { get; } = SenderId;
    public AgentId ReceiverId { get; } = ReceiverId;
    public SessionId SessionId { get; } = SessionId;
    public IReadOnlyList<ChatMessage> Messages { get; } = Messages;
    public IReadOnlyList<AuditEntry> History   { get; } = History;
    public string? LlmId { get; } = LlmId;

    private string? _textContent;
    public string TextContent =>
        _textContent ??= string.Join(" ", Messages.Select(m => m.Text ?? ""));
}
```

All 9 detectors that currently do `string.Join(" ", ctx.Messages.Select(...))` switch to `ctx.TextContent`. The string is allocated once per context regardless of how many detectors read it.

**Impact:** Saves ~900 B per pipeline pass (9 detectors × 2 passes per E2E call).

**Test impact:** None — constructor signature unchanged. Existing tests that use positional init or `new SentinelContext(...)` continue to compile.

---

### Change 2 — All detectors: static `DetectorId` + cached clean `DetectionResult`

**Files:** All 30 detector files + `StubDetector.cs`

Replace the per-call `new DetectorId(...)` property with a static field, and pre-build the clean result:

```csharp
// Before
public DetectorId Id => new("SEC-01");
return ValueTask.FromResult(DetectionResult.Clean(Id));

// After
private static readonly DetectorId _id    = new("SEC-01");
private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

public DetectorId Id => _id;
return ValueTask.FromResult(_clean);   // zero allocation on clean path
```

`StubDetector` base class gets the same treatment so all stub subclasses inherit it.

**Impact:** Saves ~88 B per detector per pipeline pass (~5,280 B per E2E call across 30 detectors × 2 passes).

**Test impact:** None — `Id` property still returns the same value, `DetectionResult.Clean` still returns equivalent results (equality on records compares by value).

---

### Change 3 — `DetectionPipeline`: sync fast-path + ArrayPool

**File:** `src/AI.Sentinel/Detection/DetectionPipeline.cs`

Replace LINQ-based `Task.WhenAll` with a two-phase approach:

1. Collect all `ValueTask<DetectionResult>` into a pooled array
2. If all are `IsCompletedSuccessfully` (the rule-based fast path), extract `.Result` directly — no `Task` objects allocated
3. Otherwise fall back to `AsTask()` + `Task.WhenAll` for genuinely async detectors

Also replace `results.Where(...).ToList()` and `results.Select(...)` LINQ chains with plain loops.

```csharp
public async ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct)
{
    var vTasks = ArrayPool<ValueTask<DetectionResult>>.Shared.Rent(_detectors.Length);
    DetectionResult[] results;
    try
    {
        for (int i = 0; i < _detectors.Length; i++)
            vTasks[i] = _detectors[i].AnalyzeAsync(ctx, ct);

        if (AllCompletedSuccessfully(vTasks, _detectors.Length))
        {
            results = new DetectionResult[_detectors.Length];
            for (int i = 0; i < _detectors.Length; i++)
                results[i] = vTasks[i].Result;
        }
        else
        {
            var tasks = new Task<DetectionResult>[_detectors.Length];
            for (int i = 0; i < _detectors.Length; i++)
                tasks[i] = vTasks[i].AsTask();
            results = await Task.WhenAll(tasks).ConfigureAwait(false);
        }
    }
    finally { ArrayPool<ValueTask<DetectionResult>>.Shared.Return(vTasks); }

    // LLM escalation path unchanged
    if (_escalationClient is not null) { /* existing logic */ }

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
    return new PipelineResult(ThreatRiskScore.Aggregate(scores), nonClean);
}
```

**Impact:** Saves ~3,000 B per pipeline pass on the sync path (eliminates 30 `Task<DetectionResult>` boxings). Combined with Change 2 (cached clean results), the sync path returns `ValueTask.FromResult(_clean)` which is a value-type `ValueTask` with no heap allocation — so `IsCompletedSuccessfully` is `true` and `.Result` is available immediately.

**Test impact:** `DetectionPipeline` tests that verify results still pass — output is identical. Tests for async/LLM-escalating detectors still exercise the slow path.

---

### Change 4 — `RepetitionLoopDetector`: span-based single-pass rewrite

**File:** `src/AI.Sentinel/Detectors/Operational/RepetitionLoopDetector.cs`

Replace `Split → Select(ToLowerInvariant) → ToList → GroupBy` with a span-based split and an `OrdinalIgnoreCase` dictionary:

```csharp
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
```

Key improvements:
- `text.AsSpan().Split(...)` returns a `SpanSplitEnumerator` — no array allocation
- `OrdinalIgnoreCase` comparison on the dictionary eliminates `.ToLowerInvariant()` per sentence
- Single pass: no `ToList()`, no `GroupBy()`
- Uses `ctx.TextContent` (Change 1)

**Impact:** 453 ns / 912 B → ~80 ns / ~150 B for a clean short input.

**Test impact:** Existing `RepetitionLoop` tests verify the 3× repetition threshold and must still pass. Behaviour is identical — case-insensitive repeated sentence detection, same threshold.

---

## Expected post-optimisation numbers

| Benchmark | Before | After (projected) |
|---|---|---|
| Pipeline — all-30 / clean | 7,864 B | ~1,300 B |
| E2E — clean short / all-30 | 16,048 B | ~2,800 B |
| Detector — RepetitionLoop / clean | 912 B | ~150 B |
| E2E — clean short / empty | 232 B | 232 B (unchanged) |

The clean-path latency improvement tracks the allocation reduction: fewer GC collections, fewer cache misses, fewer pointer-chasing allocations in the hot path.

## What is NOT changed

- `IDetector` interface — unchanged
- `SentinelChatClient` — unchanged
- `InterventionEngine` — unchanged
- `RingBufferAuditStore` — already zero-alloc on sequential path
- Any public API or NuGet package shape
- Test assertions — all existing tests must pass

## Files touched

| File | Change |
|---|---|
| `src/AI.Sentinel/Detection/SentinelContext.cs` | record → class, add `TextContent` |
| `src/AI.Sentinel/Detection/DetectionPipeline.cs` | sync fast-path, ArrayPool, remove LINQ |
| `src/AI.Sentinel/Detectors/StubDetector.cs` | static `_id` + `_clean` |
| All 30 detector files | static `_id` + `_clean`, use `ctx.TextContent` |
| `src/AI.Sentinel/Detectors/Operational/RepetitionLoopDetector.cs` | full rewrite |
