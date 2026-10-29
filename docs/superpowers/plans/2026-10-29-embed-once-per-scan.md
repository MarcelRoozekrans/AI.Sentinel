# Embed Once Per Scan, Per Pipeline: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each detection pipeline embeds every new text once per scan, on its own generator, with per-input failure isolation. This fixes #435 and #508.

**Architecture:**
- Each pipeline gets an internal `EmbeddingScope` holding its generator, scan cache and example cache.
- Before the detectors run, `DetectionPipeline.RunAsync` collects the texts of every enabled semantic detector. It embeds them through `ScanEmbedder`: one batch, then a per-input retry with an outage cut-off. It passes the resulting `ScanEmbeddings` to each detector through the internal `AnalyzeAsync` overload.
- Example-phrase vectors live in a per-detector store keyed by generator instance, filled single-flight.

**Tech Stack:** .NET 10 (SDK 10.0.403 pinned in `global.json`), Microsoft.Extensions.AI, xUnit v3, Microsoft.Extensions.DependencyInjection.

**Spec:** `docs/superpowers/specs/2026-10-29-embed-once-per-scan-design.md`. Read it first; the D/C labels below refer to it.

## Global Constraints

- **Public API:** no change to the public `IDetector`, `IEmbeddingCache`, `SentinelContext` or `SemanticDetectorBase` API. Every new type and member is `internal`.
- **Public path:** the public `SemanticDetectorBase.AnalyzeAsync(ctx, ct)` keeps using the constructor's `SentinelOptions` generator and caches.
- **Scores:** no score or severity changes for the same input and generator. ComplianceEval output must be identical apart from its `Run yyyy-MM-dd` line.
- **No cross-generator mixing:** vectors from one generator are never compared with vectors from another.
- **Failure messages** never contain an input text.
- **Cancellation:** `OperationCanceledException` always propagates and is never reported as a failure.
- **Fakes:** tests that prove fan-out or concurrency use the yielding async fake from Task 1, never a synchronous fake.
- **Running tests:** `dotnet test tests/AI.Sentinel.Tests --filter-not-class "*DetectorRegistrationTrimTests"`.
- **Commits:** one commit per task. No Claude trailer. No nested parentheses in commit bodies.
- **Style:** match the surrounding code's comment density and its `<summary>`/`<remarks>` style. Line comments say why, not what.

## Review Focus

These failure modes are not covered by any spec test. Each has a test assigned to the task that owns the code.

1. **Two semantic detectors whose texts overlap only partly.** One overrides `GetTextsToScore` to score user messages only. The union must embed each distinct text once, and each detector must score only its own texts. → Task 3, `Overlapping_texts_across_detectors_embed_once_and_score_own_texts`.
2. **Every scan text already in the scan cache.** No generator call may happen for scan texts. → Task 3, `Warm_scan_cache_makes_no_scan_call`.
3. **A provider that returns vectors in the right count but for a batch of one.** The count must be checked on single-input calls too. → Task 2, `Single_input_count_mismatch_records_failure`.
4. **A scan where the legacy `GetText` override returns blank.** That detector contributes no texts and stays Clean before its rule layer runs, as today. → Task 3, `Legacy_blank_GetText_contributes_no_texts`.
5. **The same generator used inside a pipeline and through the public path.** Examples must be embedded once. → Task 1, `Public_and_pipeline_paths_share_example_vectors_for_same_generator`.

---

## File Structure

- **Create** `src/AI.Sentinel/Detection/EmbeddingScope.cs`: the pipeline's generator and caches, and the D2 resolution.
- **Create** `src/AI.Sentinel/Detection/ScanEmbedder.cs`: `ScanEmbeddings`, plus batch, retry and cut-off embedding for one scan.
- **Modify** `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`:
  - add the per-generator example store, `TextsToEmbed` and the scan-aware overload;
  - remove `_highVectors`, `_mediumVectors`, `_lowVectors`, `_initLock` and `_initialized`.
- **Modify** `src/AI.Sentinel/Detection/DetectionPipeline.cs`: the scope constructor parameter, the precompute step and once-per-scan reporting.
- **Modify** `src/AI.Sentinel/ServiceCollectionExtensions.cs`: the `DefaultEmbeddingScope` singleton, scope wiring in `BuildDetectionPipeline`, and the inert warning.
- **Create** `tests/AI.Sentinel.Tests/Helpers/YieldingEmbeddingGenerator.cs`.
- **Create** these test files:
  - `tests/AI.Sentinel.Tests/Detection/ExampleVectorStoreTests.cs`
  - `tests/AI.Sentinel.Tests/Detection/ScanEmbedderTests.cs`
  - `tests/AI.Sentinel.Tests/Detection/EmbedOncePerScanTests.cs`
  - `tests/AI.Sentinel.Tests/NamedPipelineEmbeddingTests.cs`
- **Modify** these docs:
  - `website/docs/configuration/named-pipelines.md`
  - `website/docs/configuration/embedding-cache.md`
  - the "how semantic detectors score" section of `website/docs/detectors/overview.md`
  - the `SemanticDetectorBase` XML remarks.

---

### Task 1: Per-generator example vectors with single-flight

**Files:**
- Create: `tests/AI.Sentinel.Tests/Helpers/YieldingEmbeddingGenerator.cs`
- Modify: `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`. Replace `EnsureInitializedAsync` and `EmbedExamplesAsync` (lines ~355–415) and the vector fields.
- Test: `tests/AI.Sentinel.Tests/Detection/ExampleVectorStoreTests.cs`

**Interfaces:**
- Produces:
  - `internal sealed record ExampleVectors(ReadOnlyMemory<float>[] High, ReadOnlyMemory<float>[] Medium, ReadOnlyMemory<float>[] Low)`, nested in or next to `SemanticDetectorBase`.
  - `internal Task<ExampleVectors> GetExampleVectorsAsync(IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, CancellationToken ct)` on `SemanticDetectorBase`.
  - The test helper `YieldingEmbeddingGenerator(Func<IReadOnlyList<string>, bool>? failWhen = null)`:
    - It awaits `Task.Delay(1, ct)`, then embeds like `FakeEmbeddingGenerator`.
    - It throws `HttpRequestException("rejected")` when `failWhen(inputs)` is true.
    - It exposes `int Calls`, `IReadOnlyList<IReadOnlyList<string>> Batches` and `IReadOnlyList<string> Inputs`, all thread-safe behind a lock.
    - Optionally `TaskCompletionSource? Gate`: when set, every call awaits it before embedding.

- [ ] **Step 1: Write the failing tests** in `ExampleVectorStoreTests`. Use a test subclass of `SemanticDetectorBase` with three High, two Medium and one Low examples.
  - `Concurrent_first_uses_embed_examples_once_per_generator`: 20 concurrent `GetExampleVectorsAsync(gen, null, ct)` calls with a `Gate` that is released after all 20 have started. Assert that `gen.Calls == 3`, one call per non-empty bucket, as today.
  - `Two_generators_get_their_own_vectors`: with genA and genB, each is called 3 times and the results are not the same instance.
  - `Failed_first_use_is_retried_on_next_call`:
    - `failWhen` throws on the first call only.
    - The first call throws `HttpRequestException`.
    - The second call succeeds, and `Calls` grows.
  - `Cancelled_first_caller_does_not_fail_other_waiters`:
    - Caller 1 uses a CTS that it cancels while the call is gated.
    - Caller 2 uses `CancellationToken.None`.
    - Release the gate. Caller 1 throws `OperationCanceledException`; caller 2 returns vectors.
  - `Waiter_with_cancelled_token_propagates`: caller 2's own token is cancelled → `OperationCanceledException`.
  - `Example_cache_hits_skip_the_generator`: with every example pre-set in an `InMemoryLruEmbeddingCache`, `Calls == 0`. This mirrors the existing `ExampleEmbeddingCacheTests`.
  - `Public_and_pipeline_paths_share_example_vectors_for_same_generator`:
    - Construct the detector with `new SentinelOptions { EmbeddingGenerator = gen }`.
    - Call the public `AnalyzeAsync` on a one-message context, then `GetExampleVectorsAsync(gen, null, ct)`.
    - Assert that the example inputs were embedded once: each example string appears once in `gen.Inputs`.

- [ ] **Step 2: Run, verify they fail.** `dotnet test tests/AI.Sentinel.Tests --filter-class "*ExampleVectorStoreTests"`. Expected: a compile error, because `GetExampleVectorsAsync` is not defined.

- [ ] **Step 3: Implement.**
  - **The store.** A `ConditionalWeakTable<IEmbeddingGenerator<string, Embedding<float>>, ExampleSlot>` field per detector instance. `ExampleSlot` holds `Task<ExampleVectors>?` behind a `lock`.
  - **`GetExampleVectorsAsync`:**
    - Take the slot's task or start one. The bucket-embedding body is today's `EmbedExamplesAsync`, unchanged, including the count check and the example-cache `Set`. It runs on the starting caller's `ct`.
    - Await the task with `WaitAsync(ct)`, so a waiter's own cancellation propagates.
    - If the task faults or is cancelled, clear the slot, but only if it still holds that task.
    - If the task was cancelled and the caller's `ct` was not, retry once with a fresh task.
  - **The public path.** In `AnalyzeAsync`, replace `EnsureInitializedAsync` with `GetExampleVectorsAsync(_generator, _exampleCache, ct)`. `Classify` takes the `ExampleVectors` as a parameter.
  - Delete `_highVectors`, `_mediumVectors`, `_lowVectors`, `_initLock` and `_initialized`.

- [ ] **Step 4: Run** the new tests plus `--filter-class "*SemanticDetectorBaseTests"`, `"*ExampleEmbeddingCacheTests"` and `"*RuleFastPathTests"`. Expected: all pass.

- [ ] **Step 5: Commit**

  ```text
  refactor(detection): cache example vectors per generator with single-flight
  ```

---

### Task 2: ScanEmbedder with batch, per-input retry and outage cut-off

**Files:**
- Create: `src/AI.Sentinel/Detection/EmbeddingScope.cs`, `src/AI.Sentinel/Detection/ScanEmbedder.cs`
- Test: `tests/AI.Sentinel.Tests/Detection/ScanEmbedderTests.cs`

**Interfaces:**
- Consumes: `YieldingEmbeddingGenerator` from Task 1.
- Produces:
  - `internal sealed class EmbeddingScope(IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache scanCache, IEmbeddingCache? exampleCache)`, with get-only properties `Generator`, `ScanCache` and `ExampleCache`. The D2 resolution is added in Task 4.
  - `internal sealed class ScanEmbeddings`, with:
    - `bool TryGet(string text, out ReadOnlyMemory<float> vector)`
    - `int FailedCount`
    - `int TotalCount`
    - `Exception? FirstFailure`
    - `static ScanEmbeddings Empty`
  - `internal static class ScanEmbedder`, with `static Task<ScanEmbeddings> EmbedAsync(EmbeddingScope scope, IReadOnlyCollection<string> texts, CancellationToken ct)`. The texts are already distinct, ordinal.

- [ ] **Step 1: Write the failing tests.** Each uses a `YieldingEmbeddingGenerator` and a fresh `InMemoryLruEmbeddingCache`.
  - `Misses_are_embedded_in_one_batch_and_cached`: with 5 texts → `Calls == 1`, the batch has 5 inputs, and all 5 are now in `ScanCache`.
  - `Cached_texts_are_not_embedded`: with 2 of 5 pre-set → one call with 3 inputs.
  - `Batch_failure_retries_each_input_and_isolates_the_bad_one`:
    - `failWhen = batch => batch.Contains("bad")`, with texts `["a","bad","b","c"]`.
    - Expected calls: the batch, then singles for a, bad, b and c, so `Calls == 5`.
    - `FailedCount == 1`, `TryGet("bad")` is false, and the others are true.
  - `Outage_stops_after_first_two_single_failures`:
    - `failWhen = _ => true`, with 10 texts.
    - `Calls == 3`, `FailedCount == 10`, and `FirstFailure` is an `HttpRequestException`.
  - `Cut_off_does_not_apply_once_a_single_succeeded`: with `failWhen = b => b.Count > 1 || b[0] is "x" or "y"` and texts `["a","x","y","b"]` → `Calls == 5` and `FailedCount == 2`.
  - `Single_missing_input_is_not_retried`: with one text and an always-failing fake → `Calls == 1` and `FailedCount == 1`.
  - `Batch_count_mismatch_falls_back_to_single_calls`: wrap in `RecordingEmbeddingGenerator(inner, dropLast: true)`. Assert that a single call is made for each input after the batch.
  - `Single_input_count_mismatch_records_failure`: a fake that returns 0 vectors for any batch → `FailedCount == TotalCount`. Assert on the calls under the cut-off rule.
  - `Cancellation_propagates`: a cancelled token → `OperationCanceledException`, even when the generator would also fail.

- [ ] **Step 2: Run, verify they fail.** `--filter-class "*ScanEmbedderTests"`. Expected: a compile error.

- [ ] **Step 3: Implement `ScanEmbedder.EmbedAsync`.**
  - Look up every text in the scan cache, then send all misses in one `GenerateAsync` call.
  - A count mismatch on that call counts as a batch failure.
  - On any batch failure other than `OperationCanceledException`, handle the misses as follows.
    - **One miss:** the batch failure is that input's failure.
    - **More than one miss:** run one call per input, sequentially, with count checks. Track `succeeded` and `failed`. When `failed == 2 && succeeded == 0`, mark every remaining input as failed without a call.
  - `Set` every successful vector in `ScanCache`.
  - `FirstFailure` is the batch exception, or the first single exception.

- [ ] **Step 4: Run** the tests. Expected: all pass.

- [ ] **Step 5: Commit**

  ```text
  feat(detection): embed a scan's texts in one batch with per-input fallback
  ```

---

### Task 3: The pipeline embeds once per scan and reports failures once

**Files:**
- Modify: `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`, `src/AI.Sentinel/Detection/DetectionPipeline.cs`. In `DetectionPipeline`, that means the constructor, `RunAsync` and `SafeAnalyzeAsync`.
- Test: `tests/AI.Sentinel.Tests/Detection/EmbedOncePerScanTests.cs`

**Interfaces:**
- Consumes:
  - `EmbeddingScope`, `ScanEmbedder.EmbedAsync` and `ScanEmbeddings` from Task 2.
  - `GetExampleVectorsAsync` from Task 1.
- Produces:
  - **The pipeline constructor** gains `EmbeddingScope? embeddingScope = null` as its last optional parameter, after `redactByDefault`. Existing callers compile unchanged.
  - **`internal IReadOnlyList<string> TextsToEmbed(SentinelContext ctx)`** on `SemanticDetectorBase`. It returns `SelectTextsToScore(ctx)`, or `[]` when the legacy `GetText` override returns blank.
  - **`internal ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, DetectorConfiguration? configuration, EmbeddingScope scope, ScanEmbeddings scan, CancellationToken ct)`**, which replaces the scope-less internal overload's role inside the pipeline:
    - the rule layer runs as today;
    - then `GetExampleVectorsAsync(scope.Generator, scope.ExampleCache, ct)`;
    - then each of its `TextsToEmbed` is scored if `scan.TryGet` succeeds; a text not in the map is skipped;
    - it never calls the generator for scan texts.

- [ ] **Step 1: Write the failing tests.**
  - **Setup.** Build a `DetectionPipeline` directly with `embeddingScope: new EmbeddingScope(gen, new InMemoryLruEmbeddingCache(), null)`, using `YieldingEmbeddingGenerator`. Use 6 test semantic detectors with distinct examples, plus a capturing `onDetectorFailure`.
  - `Scan_embeds_each_text_once_across_all_detectors`:
    - Use a context with 2 new messages.
    - Exclude the example calls: count only the batches whose inputs are all scan texts.
    - Exactly one scan batch, holding the 2 texts.
  - `Overlapping_texts_across_detectors_embed_once_and_score_own_texts`:
    - Detector U overrides `GetTextsToScore` to score user messages only. Its only High example equals the **assistant** text.
    - Detector A scores every message. Its only High example equals the assistant text too.
    - Use one user message and one assistant message.
    - Expected: one scan batch with 2 inputs. A reports High. U is Clean, which proves it did not score the assistant vector it never asked for.
  - `Warm_scan_cache_makes_no_scan_call`: pre-set both texts in the scope's cache → no scan batch.
  - `Bad_input_only_skips_itself`:
    - `failWhen` covers a batch containing the marked text.
    - A detector whose High example equals the other text still reports High.
    - `onDetectorFailure` is called exactly once.
    - The message contains `"1 of 2"` and does not contain the marked text.
  - `Example_failure_is_reported_once_per_scan`:
    - `failWhen` covers any batch that contains an example phrase of one specific detector.
    - That detector is Clean, the others run, `onDetectorFailure` is called once, and the message names that detector id.
  - `Legacy_blank_GetText_contributes_no_texts`: a detector with an obsolete `GetText` override that returns `""` → Clean, and it adds nothing to the scan batch.
  - `Pipeline_without_scope_uses_detector_options`: no `embeddingScope`, and the detector is constructed with `gen` in its options → still detects, as today. This is a regression guard.
  - `Cancellation_propagates_from_precompute`: a cancelled token → `OperationCanceledException`, and no failure report.

- [ ] **Step 2: Run, verify they fail.** `--filter-class "*EmbedOncePerScanTests"`.

- [ ] **Step 3: Implement.**
  - **Semantic detectors.** In the constructor, record the indices of the enabled `SemanticDetectorBase` detectors.
  - **Precompute step.** In `RunAsync`, when `_embeddingScope` is not null and there is at least one semantic detector, before the detectors start:
    1. Collect `TextsToEmbed` per semantic detector, and union them into an ordinal `HashSet`.
    2. Start `GetExampleVectorsAsync` for each semantic detector and `ScanEmbedder.EmbedAsync` for the union, concurrently, and await them all.
    3. Catch each example failure other than cancellation per detector. Those detectors return `DetectionResult.Clean` this scan without being called.
    4. Report once per scan:
       - for the scan, when `FailedCount > 0`;
       - once for all failed example detectors together.
  - **Reporting.** Use `_logger?.LogWarning(ex, …)` and `_onDetectorFailure?.Invoke(message)`, with this exact copy:

    ```text
    AI.Sentinel: {failed} of {total} texts could not be embedded and were skipped for this scan ({ExType}: {ExMessage}). Other texts and detectors still ran.
    AI.Sentinel: the example phrases of detector(s) {id1, id2} could not be embedded, so they were skipped for this scan ({ExType}: {ExMessage}). Other detectors still ran.
    ```

  - **`SafeAnalyzeAsync`.** For a semantic detector, when a scope is present, call the new overload with the scope and the scan.
  - Keep the existing try/catch as the last line of defence.

- [ ] **Step 4: Run** the new tests and the whole suite. Expected: all pass. Existing pipeline tests construct without a scope and are unaffected.

- [ ] **Step 5: Commit**

  ```text
  fix(detection): embed each text once per scan and isolate failed inputs
  ```

  Add `Fixes #435.` to the commit body.

---

### Task 4: A scope per pipeline in DI, and the inert warning

**Files:**
- Modify: `src/AI.Sentinel/Detection/EmbeddingScope.cs`, `src/AI.Sentinel/ServiceCollectionExtensions.cs`. In `ServiceCollectionExtensions`, that covers:
  - `RegisterPipeline`, lines ~69–126;
  - `BuildDetectionPipeline`, line ~249;
  - `InertSemanticWarning` and `InertSemanticMessage`, lines ~439–480.
- Test: `tests/AI.Sentinel.Tests/NamedPipelineEmbeddingTests.cs`; update `SemanticDetectionDiagnosticsTests` and `NamedPipelineTests` where they assert the old hint.

**Interfaces:**
- Consumes: `EmbeddingScope` and the `DetectionPipeline(..., embeddingScope)` parameter from Task 3.
- Produces:
  - `internal static EmbeddingScope? EmbeddingScope.Resolve(SentinelOptions options, EmbeddingScope? inherited)`, which implements the D2 table:
    - `options.EmbeddingGenerator` set → `new(gen, options.EmbeddingCache ?? new InMemoryLruEmbeddingCache(), options.ExampleEmbeddingCache)`;
    - otherwise, `inherited` null → `null`;
    - otherwise → `new(inherited.Generator, options.EmbeddingCache ?? inherited.ScanCache, options.ExampleEmbeddingCache ?? inherited.ExampleCache)`.
  - `internal sealed record DefaultEmbeddingScope(EmbeddingScope? Scope)`, registered as a singleton in the default branch from `sp.GetRequiredService<SentinelOptions>()`, which is the resolved options. That gives C2 reference equality.

- [ ] **Step 1: Write the failing tests.** Use real `AddAISentinel` / `AddAISentinel(name, …)` registrations and a `YieldingEmbeddingGenerator` per pipeline. Resolve the `IDetectionPipeline`s by key and scan a message that one detector's High example matches.
  - `Named_pipeline_with_own_generator_uses_it`: default genA and named genB. A scan through "strict" calls genB for scan texts and examples, and genA gets 0 calls.
  - `Named_pipeline_without_generator_inherits_default`: a scan through the named pipeline uses genA.
  - `Named_pipeline_with_own_generator_ignores_default_caches`:
    - The default has `EmbeddingCache = cacheA` and `ExampleEmbeddingCache = exA`; the named pipeline has genB and no caches.
    - After a scan through the named pipeline, cacheA and exA received no `Set`. Use a recording cache.
  - `Inheriting_named_pipeline_shares_default_scan_cache_instance`: neither pipeline sets a cache. Scan text T through the default, then through the named pipeline → genA embeds T once.
  - `Named_pipeline_own_cache_with_inherited_generator`: the named pipeline sets `EmbeddingCache = cacheN` only → T is `Set` in cacheN, and genA is used.
  - `Container_generator_reaches_named_pipeline_through_default`: register an `IEmbeddingGenerator` in the container, with no generator on either pipeline → the named pipeline uses it.
  - `Named_pipeline_with_own_generator_is_not_inert`: the default has no generator, the named pipeline has genB → resolving the named pipeline logs no inert warning. Use the existing capture pattern in `SemanticDetectionDiagnosticsTests`.
  - **Rewrite** the existing named-inert hint assertion to the new copy:

    ```text
    Set EmbeddingGenerator on this pipeline's options or on the default AddAISentinel call, or register an IEmbeddingGenerator<string, Embedding<float>> in the container with UseEmbeddingGeneratorFromServices left on for the default pipeline.
    ```

- [ ] **Step 2: Run, verify they fail.** `--filter-class "*NamedPipelineEmbeddingTests"`.

- [ ] **Step 3: Implement.**
  - **`EmbeddingScope.Resolve`.**
  - **Registration.**
    - Register `DefaultEmbeddingScope` in the default branch.
    - In `BuildDetectionPipeline`, pass `EmbeddingScope.Resolve(opts, inherited)`.
      - The default pipeline uses `sp.GetRequiredService<DefaultEmbeddingScope>().Scope`.
      - A named pipeline uses `Resolve(opts, sp.GetService<DefaultEmbeddingScope>()?.Scope)`.
  - **`InertSemanticWarning`.** The effective generator is:
    - the default pipeline's: `opts.EmbeddingGenerator`, which is already resolved;
    - a named pipeline's: `opts.EmbeddingGenerator ?? sp.GetService<SentinelOptions>()?.EmbeddingGenerator`.

    Update its remarks and the hint copy above.

- [ ] **Step 4: Run** the new and updated tests, then the whole suite. Expected: all pass.

- [ ] **Step 5: Commit**

  ```text
  fix(pipelines): honour a named pipeline's embedding generator and caches
  ```

  Add `Fixes #508.` to the commit body.

---

### Task 5: Docs and score verification

**Files:**
- Modify:
  - `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`: the class `<remarks>`;
  - `website/docs/configuration/named-pipelines.md`;
  - `website/docs/configuration/embedding-cache.md`;
  - `website/docs/detectors/overview.md`, in the `#how-semantic-detectors-score` section.

- [ ] **Step 1: Update the docs.**
  - **Each scan embeds a text once.** Within a pipeline, each new text is embedded once per scan, in one batch, whatever the number of semantic detectors.
  - **Failures.**
    - A rejected input is skipped by itself.
    - After two single-input failures with no success, the rest of the scan's texts are skipped.
    - A failure is reported once per scan.
  - **Named pipelines.**
    - Add the D2 table.
    - Remove every statement that a named pipeline's generator is ignored or that the detectors use the default pipeline's generator.
  - **`embedding-cache.md`.**
    - A scan cache is per pipeline when it is unset, no longer per detector.
    - Example vectors are kept per generator.

- [ ] **Step 2: Run the docs guard.** `--filter-class "*DetectorDocumentationTests"`. Expected: PASS.

- [ ] **Step 3: Verify scores.**
  - Run `dotnet run --project tools/AI.Sentinel.ComplianceEval -- --out /tmp/after.md` on this branch.
  - Run the same command into `/tmp/before.md` from a `git worktree` of `origin/main`.
  - `diff <(grep -v '^Model `' /tmp/before.md) <(grep -v '^Model `' /tmp/after.md)`. Expected: no output, and exit code 0 for both runs.
  - If the model can't be downloaded in this environment, say so in the PR. Do not claim the scores are verified.

- [ ] **Step 4: Run the full suite.** Run `dotnet test tests/AI.Sentinel.Tests --filter-not-class "*DetectorRegistrationTrimTests"`, then `dotnet build -warnaserror` for the solution. Expected: all green, 0 warnings.

- [ ] **Step 5: Commit**

  ```text
  docs: one embedding per text per scan, and per-pipeline generators
  ```
