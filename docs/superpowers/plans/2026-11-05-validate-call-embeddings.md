# Validate call-text embeddings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Call-text vectors that are empty, zero-norm, non-finite or of the wrong length are never cached or scored. A semantic detector that needed such a text reports `TextsNotEmbedded` instead of silently reading Clean.

**Architecture:** `ScanEmbedder` validates every cached hit and fresh vector with `InvalidEmbeddingException.Problem` and an expected dimension. An unusable one counts as a failed text in `ScanEmbeddings.FailedCount`. The pipeline awaits the example vectors before it embeds the scan texts, so it can pass their dimension. The standalone detector path and the approval matcher get the same checks.

**Tech Stack:** C# / .NET 8 + 10, Microsoft.Extensions.AI, xunit v3 on Microsoft.Testing.Platform.

**Spec:** `docs/superpowers/specs/2026-11-05-validate-call-embeddings-design.md`

## Global Constraints

- **No public API change.** Reuse `DetectorFailureKind.TextsNotEmbedded`; add no enum value or public member. This is a `fix:`, for 5.1.x.
- **Validation is `InvalidEmbeddingException.Problem` plus a length check** against `InvalidEmbeddingException.DimensionMismatch`. Do not write a second validator.
- **Failure messages never contain an input text.** `InvalidEmbeddingException` messages carry the kind only.
- **Cancellation rule unchanged:** an `OperationCanceledException` propagates only when the caller's token is cancelled.
- **Tests:** run them only with a filter, never as an unfiltered `dotnet test`. Use `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~<Class>"`, and repeat with `-f net8.0` at the end of each task.
- **Commits:** conventional, no nested parentheses in the body, no Claude signature or session link. Run `dotnet format whitespace --verify-no-changes` before each commit.

## Review Focus

1. **A persistent cache entry from before this fix holding a zero vector.** It must be re-embedded on the next scan and then flag the text. Pinned in Task 2, `Invalid_cached_vector_is_re_embedded_and_the_text_flags`.
2. **A batch where only one input's vector is bad.** The others must still be cached and scored, and the bad one must not trigger per-input retries. Pinned in Task 1, `Invalid_vector_in_a_batch_fails_only_that_text`.
3. **A provider that switches models, giving cached vectors of the old length.** They must be re-embedded, not scored at 0. Pinned in Task 1 `Wrong_length_cached_hit_is_re_embedded` and Task 2.
4. **A scan where every detector's examples failed.** There is no expected dimension, and failure reporting must stay as it is today. Pinned in Task 2, `Scan_without_example_dimension_still_reports_examples_not_embedded`.
5. **Approvals: a bad vector followed by a good one for the same arguments.** The second call must be scored, not `Failed`. Pinned in Task 4.

---

### Task 1: `ScanEmbedder` validates vectors

**Files:**
- Create: `tests/AI.Sentinel.Tests/Helpers/VectorEmbeddingGenerator.cs`
- Modify: `src/AI.Sentinel/Detection/ScanEmbedder.cs`
- Modify: `src/AI.Sentinel/Detection/ScanEmbeddings.cs`, XML doc of `FailedCount`
- Modify: callers `src/AI.Sentinel/Detection/DetectionPipeline.cs` (`EmbedTextsAsync`) and `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalMatcher.cs`, passing `null` for now
- Test: `tests/AI.Sentinel.Tests/Detection/ScanEmbedderTests.cs`

**Interfaces:**
- Produces: `ScanEmbedder.EmbedAsync(EmbeddingScope scope, IReadOnlyCollection<string> texts, int? expectedDimension, CancellationToken ct)`. The parameter is placed before `ct`, with no default value, so every caller states it.
- Produces: the test helper `public sealed class VectorEmbeddingGenerator(Func<string, float[]> vectors) : IEmbeddingGenerator<string, Embedding<float>>` with `int Calls` and `List<IReadOnlyList<string>> Batches`. This replaces the private copies only where a task touches the file; leave other private copies alone.

- [ ] **Step 1: Write the failing tests** in `ScanEmbedderTests`. Use `VectorEmbeddingGenerator` and `float[] Good = [1f, 0f, 0f]`.
  - `Unusable_fresh_vector_is_not_cached_and_counts_as_failed` is a `[Theory]` over `[]`, `[0f,0f,0f]`, `[float.NaN,1f,0f]` and `[1f,0f]` with `expectedDimension: 3`. It expects kinds `EmptyVector`, `InvalidVector`, `InvalidVector` and `DimensionMismatch`. Assert `FailedCount == 1`, `!result.TryGet("x", out _)`, `!cache.TryGet("x", out _)`, and `Assert.IsType<InvalidEmbeddingException>(result.FirstFailure).Kind == expectedKind`.
  - `Invalid_vector_in_a_batch_fails_only_that_text`: texts `["a","bad","b"]`, where "bad" maps to a zero vector. Assert `gen.Calls == 1` (no retries), `FailedCount == 1`, and that "a" and "b" are in both the result and the cache.
  - `Invalid_vectors_do_not_count_as_an_outage`: 10 texts, where the first two map to zero vectors and the rest to `Good`. Assert `gen.Calls == 1` and `FailedCount == 2`.
  - `Invalid_cached_hit_is_re_embedded`: pre-set the cache with a zero vector for "a". The generator returns `Good`. Assert `gen.Batches[0] == ["a"]`, `FailedCount == 0`, and that the cache now holds `Good`.
  - `Wrong_length_cached_hit_is_re_embedded`: as above, with a cached `[1f,0f]` and `expectedDimension: 3`.
  - `Without_expected_dimension_the_first_usable_vector_sets_it`: texts `["a","b","c"]` map to lengths 3, 2 and 3 with `expectedDimension: null`. Assert that only "b" failed with `DimensionMismatch`.
  - `Unusable_single_retry_vector_counts_as_failed`: the batch throws, and the per-input retry for "bad" returns a zero vector. Assert `FailedCount == 1`, that "bad" is not cached, and that `FirstFailure` is still the batch exception.
  - Update every existing `EmbedAsync` call in the file to pass `expectedDimension: null`.

- [ ] **Step 2: Run them and check that they fail.** Run `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~ScanEmbedderTests"`. Expected: a build error, because the `expectedDimension` parameter does not exist.

- [ ] **Step 3: Implement it in `ScanEmbedder.cs`.**
  - A cached hit is used only when it is usable for the current dimension. A cached hit that is usable and arrives with no expected dimension sets the dimension.
  - `Store` becomes a check-then-store that returns the failure. It returns `InvalidEmbeddingException?`, stores and caches only a usable vector, and fixes the dimension from the first usable vector when there is none.
  - In `TryBatchAsync`, an unusable vector adds to a failed count and records the first `InvalidEmbeddingException`. The batch is still "ok", so no retry happens. Return the count so `EmbedAsync` builds `ScanEmbeddings` with it.
  - In `RetryEachAsync`, an unusable single vector counts as failed, and `firstFailure ??=` it. It does **not** count towards `failed` for the outage cut-off: use a separate counter, so `failed >= OutageFailures && succeeded == 0` still means two thrown failures.
  - Update the class `<summary>`/`<remarks>` and `ScanEmbeddings.FailedCount`'s doc to say that an unusable vector counts as a failed text and is never cached.
  - Pass `null` at the two callers. Tasks 2 and 4 wire the real value.

- [ ] **Step 4: Run the tests and check that they pass.** Use the Step 2 command, then `--filter "FullyQualifiedName~EmbedOncePerScanTests|FullyQualifiedName~SemanticApprovalMatcherTests"`. Expected: all pass.

- [ ] **Step 5: Commit.** `fix(detection): ScanEmbedder never caches or scores an unusable vector`

### Task 2: The pipeline passes the example dimension

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`, `EmbedScanAsync`, `EmbedExamplesAsync` and `EmbedTextsAsync`
- Modify: `src/AI.Sentinel/Detection/DetectorFailureKind.cs`, XML doc of `TextsNotEmbedded`
- Test: `tests/AI.Sentinel.Tests/Detection/EmbedOncePerScanTests.cs`

**Interfaces:**
- Consumes: `ScanEmbedder.EmbedAsync(scope, texts, int? expectedDimension, ct)` from Task 1.
- Produces: private `EmbedExamplesAsync` returns `Task<(Exception? Failure, int? Dimension)>`; `Dimension` is the length of the first vector in the first non-empty tier when the examples embedded. `EmbedTextsAsync(scope, texts, int? expectedDimension, ct)`.

- [ ] **Step 1: Write the failing tests** in `EmbedOncePerScanTests`, with its `TestSemantic`, `Pipeline`, `Ctx` and `User` helpers and a `VectorEmbeddingGenerator`. Map the example phrase and `FirstText` to the same `Good` vector, so a valid answer flags at High.
  - `Zero_vector_text_reports_texts_not_embedded_and_is_not_cached`: `FirstText` maps to `[0,0,0]`. Assert `result.Failures == [new DetectorFailure(new("TST-A"), DetectorFailureKind.TextsNotEmbedded)]`, `!Fired(result, "TST-A")`, and that exactly one failure message contains `InvalidEmbeddingException`. Then switch the generator's function to return `Good` for `FirstText`, run again on the same pipeline, and assert `Has(result, "TST-A", Severity.High)` and no failures.
  - `Invalid_cached_vector_is_re_embedded_and_the_text_flags`: pre-set the pipeline's scan cache with a zero vector for `FirstText`. The generator returns `Good`. Assert High and no failures.
  - `Wrong_length_scan_vector_reports_texts_not_embedded`: examples have length 3 and `FirstText` length 2. Assert `TextsNotEmbedded`, with a `DimensionMismatch` kind in the message.
  - `Scan_without_example_dimension_still_reports_examples_not_embedded`: the example phrase maps to `[0,0,0]`. Assert `ExamplesNotEmbedded` for the detector and nothing else.
  - If the `Pipeline` helper does not expose the scan cache, add an optional `IEmbeddingCache? scanCache` parameter to it.

- [ ] **Step 2: Run them and check that they fail.** Run `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~EmbedOncePerScanTests"`. Expected: the wrong-length test fails, because it scores Clean with no failure. The others may already pass through Task 1, which is fine; they pin the behaviour.

- [ ] **Step 3: Implement it in `DetectionPipeline.cs`.** Start the example tasks as today, `await Task.WhenAll(exampleTasks)`, take the dimension of the first semantic detector, in `_semanticIndices` order, whose examples succeeded, then start `EmbedTextsAsync(scope, union, dimension, ct)`. Keep the guarantee that every task is observed, even when one faults or is cancelled. Update the `EmbedScanAsync` remarks to say that the examples are awaited first, and why. Update the `TextsNotEmbedded` doc to say "could not be embedded, or the provider returned an unusable vector for it".

- [ ] **Step 4: Run the tests and check that they pass.** Run `--filter "FullyQualifiedName~AI.Sentinel.Tests.Detection"`. Expected: all pass. A test that asserted example and scan embedding run concurrently, or that counted call order, is updated to the new order with a one-line reason, not deleted.

- [ ] **Step 5: Commit.** `fix(detection): check scan vectors against the example dimension`

### Task 3: `SemanticDetectorBase` checks the standalone path, the scoped guard and the example tiers

**Files:**
- Modify: `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`, `GetEmbeddingsAsync`, the scoped `AnalyzeAsync` and `EmbedAllExamplesAsync`
- Test: `tests/AI.Sentinel.Tests/Detection/SemanticDetectorBaseTests.cs`

**Interfaces:**
- Consumes: `InvalidEmbeddingException`, and `ExampleVectors(High, Medium, Low)`.
- Produces: no new members. A private `static int ExampleDimension(ExampleVectors)` helper is fine if useful.

- [ ] **Step 1: Write the failing tests** in `SemanticDetectorBaseTests`.
  - `Standalone_unusable_fresh_vector_throws_and_caches_nothing`: a detector built with a `VectorEmbeddingGenerator` and an `InMemoryLruEmbeddingCache` as `EmbeddingCache`. The scan text maps to `[0,0,0]`. Assert that `AnalyzeAsync(ctx, null, ct)` throws `InvalidEmbeddingException` with `Kind == InvalidVector`, and that the cache does not hold the text.
  - `Standalone_wrong_length_fresh_vector_throws_dimension_mismatch`.
  - `Standalone_invalid_cached_hit_is_re_embedded`: the cache is pre-set with a zero vector and the generator returns `Good`. Assert that the result is High.
  - `Scoped_vector_of_other_length_throws_dimension_mismatch`: call the scoped `AnalyzeAsync` with a hand-built `ScanEmbeddings` that holds a length-2 vector for the text, while the examples have length 3. Assert that it throws `InvalidEmbeddingException(DimensionMismatch)`.
  - `Example_tiers_of_mixed_length_throw_dimension_mismatch`: High examples map to length 3 and Medium to length 2. `GetExampleVectorsAsync` throws `InvalidEmbeddingException` with `DimensionMismatch`.

- [ ] **Step 2: Run them and check that they fail.** Run `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~SemanticDetectorBaseTests"`. Expected: the new tests fail.

- [ ] **Step 3: Implement it.**
  - **`GetEmbeddingsAsync(texts, int dimension, ct)`:** the caller passes the example dimension. A cached hit that `Problem` rejects or of the wrong length is a miss. Validate all fresh vectors before any `_cache.Set`, and throw on the first unusable one, as `ExampleEmbedder.Validate` does.
  - **The scoped `AnalyzeAsync`:** for each vector it takes from `scan`, throw `InvalidEmbeddingException` on a `Problem` or a length mismatch against the examples.
  - **`EmbedAllExamplesAsync`:** after the three tiers, check that every non-empty tier has the same vector length, and throw `InvalidEmbeddingException(DimensionMismatch)` otherwise.
  - Update the remarks of both `AnalyzeAsync` overloads.

- [ ] **Step 4: Run the tests and check that they pass.** Run `--filter "FullyQualifiedName~AI.Sentinel.Tests.Detection"`. Expected: all pass.

- [ ] **Step 5: Commit.** `fix(detection): semantic detectors refuse unusable call vectors`

### Task 4: The approval matcher passes the dimension and reports the kind

**Files:**
- Modify: `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalMatcher.cs:102-106`
- Test: `tests/AI.Sentinel.Tests/Approvals/Semantic/SemanticApprovalMatcherTests.cs`

**Interfaces:**
- Consumes: `ScanEmbedder.EmbedAsync(scope, texts, int? expectedDimension, ct)`.

- [ ] **Step 1: Write the failing tests.**
  - `Invalid_call_vector_fails_with_its_kind`: the call text maps to `[0,0,0]`. Assert `SemanticMatch.Failed` with kind `InvalidEmbeddingException.InvalidVector`. Today it is the type name.
  - `Invalid_call_vector_is_not_cached_so_the_next_call_is_scored`: the first call gets a zero vector and `Failed`. Switch the generator to return the example's vector, then call again with the same arguments. Assert that the result is not `Failed`.

- [ ] **Step 2: Run them and check that they fail.** Run `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~SemanticApprovalMatcherTests"`.

- [ ] **Step 3: Implement it.** Pass `examples[0].Length`. When `FailedCount > 0`, the kind is `invalid.Kind` if `FirstFailure is InvalidEmbeddingException invalid`, and otherwise the type name as today. Leave the checks in `Score` as a second line.

- [ ] **Step 4: Run the tests and check that they pass.** Run `--filter "FullyQualifiedName~AI.Sentinel.Tests.Approvals"`. Expected: all pass.

- [ ] **Step 5: Commit.** `fix(approvals): report the kind of an unusable call vector`

### Task 5: Docs and the full check

**Files:**
- Modify: the page or pages under `website/docs` that describe the embedding cache or `TextsNotEmbedded`. Find them with `grep -rln "TextsNotEmbedded\|EmbeddingCache" website/docs`.

- [ ] **Step 1: Add one sentence where the cache or `TextsNotEmbedded` is described:** an empty, zero-norm, non-finite or wrong-length vector from the provider is never cached, and the detector reports `TextsNotEmbedded` for that scan. Also note that scan texts are embedded after the example phrases.
- [ ] **Step 2: Run the test DLL** for both TFMs with `-noclass "*DetectorRegistrationTrimTests"`. Build first with `dotnet build tests/AI.Sentinel.Tests -c Debug`, then run `tests/AI.Sentinel.Tests/bin/Debug/net10.0/AI.Sentinel.Tests -noclass "*DetectorRegistrationTrimTests"`, and the same for net8.0. Expected: all pass, apart from the 3 `DashboardCommandTests` known to fail locally on main. Report them if they fail.
- [ ] **Step 3: Run `dotnet format whitespace --verify-no-changes`.** Expected: no changes.
- [ ] **Step 4: Commit.** `docs: unusable call vectors are never cached`
