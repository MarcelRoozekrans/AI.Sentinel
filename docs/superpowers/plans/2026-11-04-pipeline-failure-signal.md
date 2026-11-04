# Pipeline Failure Signal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every scan reports which detectors did not run as configured, so a gate can treat an incomplete scan as unavailable (#550).

**Architecture:** `DetectionPipeline.RunAsync` keeps a per-scan `DetectorFailureKind?[]` indexed like `_detectors`, next to `outcomes`. Each catch site records into it, and the first kind recorded for a detector wins. `BuildResult` turns it into `PipelineResult.Failures`, an `init` property. `SentinelPipeline.ScanAsync` copies the failures out to `ScreenAsync`, which sets them on `ScreeningOutcome.Passed` and `Quarantined`.

**Tech Stack:** C# / .NET 10, xUnit v3.

**Spec:** `docs/superpowers/specs/2026-11-04-pipeline-failure-signal-design.md`

## Global Constraints

- No behaviour change: chat, hooks, MCP and `ScreenAsync` verdicts stay as they are; only the new members are added.
- `Failures` is an `init` property with default `[]`, never a positional record parameter: the public constructors and `Deconstruct` of `PipelineResult`, `ScreeningOutcome.Passed` and `ScreeningOutcome.Quarantined` must not change.
- The signal carries no exception message and no scanned text.
- A clean scan allocates no failure list: `Failures` is the shared empty `[]`. The per-scan kinds array is rented from `ArrayPool` and returned after the scan, so a clean, complete scan allocates no more than before.
- One entry per detector. The precedence follows the stages: embedding (`TextsNotEmbedded`, `ExamplesNotEmbedded`), then analysis (`Threw`, `RegexTimeout`), then review (`ReviewFailed`). The earliest recorded kind wins.
- A review skipped because `MaxReviewsPerScan` ran out is not a failure.
- `Failures` lists detectors in `_detectors` order.
- Before each push: `dotnet format whitespace --verify-no-changes`.
- Commit messages are conventional commits, with no nested parentheses in the body.

## Review Focus

1. **A semantic detector without an embedding scope whose provider is down.** It throws inside `SemanticDetectorBase.AnalyzeAsync` and must come out as `Threw`, not as clean and complete. The test goes in Task 1.
2. **A partial embedding failure.** Of two semantic detectors, only the one whose texts include the failed text is `TextsNotEmbedded`. The other one is complete. The test goes in Task 2.
3. **A rule-layer match after a text failure.** The finding stays in `Detections`, and the detector is also in `Failures`. The test goes in Task 2.
4. **An over-budget review next to a failed one.** Only the failed one is listed. The test goes in Task 3.
5. **`ScreenAsync` on a clean but incomplete text.** It returns `Passed` with `Complete == false`. `ScanAsync`'s early `IsClean` return must not drop the failures. The test goes in Task 4.

---

### Task 1: Public types, collector, analysis-stage kinds

**Files:**
- Create: `src/AI.Sentinel/Detection/DetectorFailure.cs`
- Modify: `src/AI.Sentinel/Detection/PipelineResult.cs`
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`: `RunAsync` (106), `AnalyzeAllAsync`, `SafeAnalyzeAsync` (255-305) and `BuildResult` (770)
- Test: `tests/AI.Sentinel.Tests/Detection/DetectorFailureIsolationTests.cs`

**Interfaces:**
- Produces:
  - `public enum DetectorFailureKind { Threw, RegexTimeout, TextsNotEmbedded, ExamplesNotEmbedded, ReviewFailed }`
  - `public readonly record struct DetectorFailure(DetectorId Detector, DetectorFailureKind Kind)`
  - `PipelineResult.Failures { get; init; }`, of type `IReadOnlyList<DetectorFailure>`, with default `[]`
  - `PipelineResult.Complete => Failures.Count == 0`
  - in `DetectionPipeline`: `private static void RecordFailure(DetectorFailureKind?[] failures, int index, DetectorFailureKind kind) => failures[index] ??= kind;`
  - `BuildResult(DetectionResult[] results, DetectorFailureKind?[] failures, DetectionResult? scanLimit = null)`
- Decided: `RunAsync` rents `failures` from `ArrayPool<DetectorFailureKind?>.Shared` (cleared to `_detectors.Length`, returned in a `finally`) and threads it like `outcomes`. Each detector writes only its own slot, so the concurrent analysis stage needs no locking. `BuildResult` returns the shared `[]` when every slot is null.

XML doc comments on each public member must say what each kind means, matching the spec's table.

- [ ] **Step 1: Write the failing tests** in `DetectorFailureIsolationTests`:
  - `Throwing_detector_is_listed_as_threw`: pipeline `[ThrowingDetector, FiringDetector]`. Assert `!result.Complete`, and `Assert.Equal([new DetectorFailure(new("TST-THROW"), DetectorFailureKind.Threw)], result.Failures)`.
  - `Async_throwing_detector_is_listed_as_threw`: the same with `AsyncThrowingDetector`, id `TST-THROW-ASYNC`.
  - `Regex_timeout_is_listed_and_still_critical`: a detector that throws `new RegexMatchTimeoutException("x", "y", TimeSpan.FromMilliseconds(5))`. Assert a Critical detection for it and a failure of kind `RegexTimeout`.
  - `Clean_scan_is_complete`: `[FiringDetector]` only. Assert `result.Complete` and `Assert.Empty(result.Failures)`.
  - `PipelineResult_constructed_directly_is_complete`: `new PipelineResult(ThreatRiskScore.Zero, [])`. Assert `Complete`.
- [ ] **Step 2: Run them and see them fail to compile.** Run `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~DetectorFailureIsolationTests"`. Expected: a compile error, because `Failures` and `DetectorFailure` do not exist yet.
- [ ] **Step 3: Implement.** Add the types. Thread `failures` through `RunAsync`, `AnalyzeAllAsync` and `SafeAnalyzeAsync`, using the `index` it already receives. Record `Threw` in the general catch and `RegexTimeout` in the regex catch. `BuildResult` sets `Failures` to the non-null slots in index order. The `_detectors.Length == 0` branches stay complete.
- [ ] **Step 4: Add the Review Focus #1 test** in `EmbedOncePerScanTests`, next to `Provider_timeout_without_scope_is_that_detectors_failure`: `Provider_failure_without_scope_is_listed_as_threw`. Same arrange as that test; assert one failure for that detector with kind `Threw`.
- [ ] **Step 5: Run the tests.** Run `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~DetectorFailureIsolationTests|FullyQualifiedName~EmbedOncePerScanTests"`. Expected: PASS.
- [ ] **Step 6: Commit** `feat(detection): PipelineResult reports detectors that failed in a scan`

### Task 2: Embedding-stage kinds and precedence

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`: `EmbedScanAsync` (325-381) and the scope branch of `SafeAnalyzeAsync` (264-280)
- Test: `tests/AI.Sentinel.Tests/Detection/EmbedOncePerScanTests.cs`

**Interfaces:**
- Consumes: `failures` and `RecordFailure` from Task 1.
- Records:
  - `TextsNotEmbedded` for detector `i` when `TextsFailures[i]` is set, which means its text selection threw, or when any text in `Texts[i]` has no vector (`!Scan.TryGet(text, out _)`) and `Scan.FailedCount > 0`.
  - `ExamplesNotEmbedded` when `ExamplesFailed[i]`.

  Record both before the analysis stage runs, so the `ExceptionDispatchInfo.Throw(textsFailure)` rethrow that `SafeAnalyzeAsync`'s general catch turns into `Threw` does not override `TextsNotEmbedded`. A detector with both a text failure and an example failure is `TextsNotEmbedded`, because texts are checked first.

- [ ] **Step 1: Write the failing tests**, using the arrange of the named existing tests:
  - `Bad_input_lists_only_the_detectors_that_needed_it`: two `TestSemantic` detectors. The first scores `FirstText` and `SecondText`, the second only `SecondText`, and `FirstText` fails to embed (as in `Bad_input_only_skips_itself`). Assert that `Failures` is exactly the first detector with `TextsNotEmbedded`.
  - `Example_failure_is_listed_as_examples_not_embedded`: as in `Example_failure_is_reported_once_per_scan`, assert the kind.
  - `Rule_layer_match_after_text_failure_is_still_listed`: as in `Provider_timeout_on_scan_texts_keeps_the_rule_layer_and_is_reported_once`. Assert that the rule-layer detection is present and that the detector is in `Failures` as `TextsNotEmbedded`.
  - `Throwing_text_selection_is_listed_as_texts_not_embedded`: as in `Throwing_text_selection_is_reported_as_that_detectors_failure`. Assert the kind is `TextsNotEmbedded`, not `Threw`.
  - `Texts_failure_wins_over_examples_failure`: one detector whose scan text and example phrases both fail. Assert one entry, `TextsNotEmbedded`.
  - `Warm_cache_scan_is_complete`: as in `Warm_scan_cache_makes_no_scan_call`, assert `Complete`.
- [ ] **Step 2: Run them and see them fail.** Run `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~EmbedOncePerScanTests"`. Expected: the new tests fail, with `Failures` empty or `Threw`.
- [ ] **Step 3: Implement the recording** described under Interfaces.
- [ ] **Step 4: Run the tests.** Same command as Step 2. Expected: PASS.
- [ ] **Step 5: Commit** `feat(detection): list detectors whose texts or example phrases could not be embedded`

### Task 3: Review-stage kind

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`: `ReviewAllAsync` (466-505), where `status != ReviewStatus.Answered`
- Test: `tests/AI.Sentinel.Tests/Detection/ReviewStepTests.cs`

**Interfaces:**
- Consumes: `failures` and `RecordFailure`. A failed or timed-out review records `ReviewFailed` at `candidate.Index`. Over-budget candidates (`c >= reviewed`) record nothing.

- [ ] **Step 1: Write the failing tests**, using the file's `Semantic`, `Vector`, `FakeReviewer` and `RunAsync` helpers:
  - `Failed_review_is_listed`: the reviewer throws `HttpRequestException`. Assert that `Failures` is exactly the detector with `ReviewFailed`, and that the detection keeps its capped severity.
  - `Timed_out_review_is_listed`: as in the file's existing timeout test, assert `ReviewFailed`.
  - `Over_budget_review_is_not_a_failure`: `MaxReviewsPerScan = 1` with two candidates. The reviewer answers the first and fails nothing. Assert `Complete`.
  - `Over_budget_next_to_failed_lists_only_the_failed`: `MaxReviewsPerScan = 1` with two candidates, and the reviewer throws. Assert exactly one entry, for the higher-ranked candidate.
  - `Answered_review_is_complete`: assert `Complete` on the existing confirm scenario.
- [ ] **Step 2: Run them and see them fail.** Run `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~ReviewStepTests"`. Expected: the new failure tests fail.
- [ ] **Step 3: Implement the recording** described under Interfaces.
- [ ] **Step 4: Run the tests.** Same command as Step 2. Expected: PASS.
- [ ] **Step 5: Commit** `feat(detection): list detectors whose review failed or timed out`

### Task 4: Screening outcomes and docs

**Files:**
- Modify: `src/AI.Sentinel/Screening/ScreeningOutcome.cs`: `Passed` and `Quarantined`
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`: `ScanAsync` (830) and `ScanCollectingAsync` (729)
- Modify: `src/AI.Sentinel/SentinelPipeline.Screening.cs` (60-82)
- Modify: `website/docs/screening.md`
- Modify: `website/docs/detectors/operational.md`, the `OnDetectorFailure` section
- Test: `tests/AI.Sentinel.Tests/Screening/ScreenAsyncTests.cs`

**Interfaces:**
- Consumes: `PipelineResult.Failures`.
- Produces:
  - on both `ScreeningOutcome.Passed` and `ScreeningOutcome.Quarantined`: `IReadOnlyList<DetectorFailure> Failures { get; init; } = []` and `bool Complete => Failures.Count == 0`
  - `ScanAsync` and `ScanCollectingAsync` get an optional `List<DetectorFailure>? failures = null`, filled with `AddRange(pipelineResult.Failures)` **before** the `if (pipelineResult.IsClean) return null;` line

- [ ] **Step 1: Write the failing tests** in `ScreenAsyncTests`, using the file's pipeline setup plus a throwing detector registered as a user detector:
  - `Clean_but_incomplete_text_passes_with_failures`: assert `Passed`, `!Complete`, and one `Threw` entry.
  - `Quarantined_outcome_carries_failures`: the throwing detector plus a Critical rule detector. Assert `Quarantined` with one `Threw` entry.
  - `Clean_text_is_complete`: assert `Passed.Complete`.
- [ ] **Step 2: Run them and see them fail.** Run `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~ScreenAsyncTests"`. Expected: a compile error, because `Failures` is not on the outcomes yet.
- [ ] **Step 3: Implement.** Add the members, thread `failures`, and set them with an object initializer: `new ScreeningOutcome.Passed(...) { Failures = failures }`.
- [ ] **Step 4: Update the docs.** In `screening.md`, add a section "Incomplete scans" next to the outcome table. It says what `Failures` and `Complete` mean, lists the five kinds with one line each, and shows a gate that refuses on `!Complete`:

  ```csharp
  if (outcome is ScreeningOutcome.Passed { Complete: true } passed) Persist(passed.RedactedText);
  ```

  It also says that live chat, the hooks and MCP keep their behaviour. In `operational.md`, add one sentence pointing from `OnDetectorFailure` to `PipelineResult.Failures` for per-scan correlation.
- [ ] **Step 5: Run the tests and build the docs.** Run `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~ScreenAsyncTests"`, expected PASS. Then run `cd website && npm ci && npm run build`, expected `[SUCCESS]` with no broken-link errors.
- [ ] **Step 6: Run the full suite and the format check.** Run `dotnet build -warnaserror`, then run the built test DLL `dotnet tests/AI.Sentinel.Tests/bin/Debug/net10.0/AI.Sentinel.Tests.dll -noclass "*DetectorRegistrationTrimTests"`, because the trim test AOT-publishes; CI runs it, then `dotnet format whitespace --verify-no-changes`. Expected: no warnings, and every test passes except the 3 `DashboardCommandTests` known to fail locally on main.
- [ ] **Step 7: Commit** `feat(screening): screening outcomes report incomplete scans`
