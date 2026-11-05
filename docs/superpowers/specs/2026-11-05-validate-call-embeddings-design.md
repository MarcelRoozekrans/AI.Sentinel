# Validate call-text embeddings before caching them (#568)

## Intent

`ScanEmbedder.Store` (`src/AI.Sentinel/Detection/ScanEmbedder.cs:117`) and `SemanticDetectorBase.GetEmbeddingsAsync` (`src/AI.Sentinel/Detection/SemanticDetectorBase.cs:666`) cache whatever vector the provider returns, and trust any cached hit. An empty, zero-norm or non-finite vector, or one of the wrong length, scores 0 in `CosineSimilarity`. The text then reads as Clean. With a persistent cache it keeps reading Clean after the bad response is long gone. That is a semantic detector failing open with no signal. For semantic approvals (#477) the same cached vector makes every later call with those arguments fail until the cache is cleared.

`ExampleEmbedder` already refuses such vectors since #477, through `InvalidEmbeddingException.Problem`. Call-text vectors get the same treatment, and a detector whose text had an unusable vector reports it the way it reports a provider failure.

## Decisions (Marcel, 2026-11-05)

- **Failure kind: reuse `DetectorFailureKind.TextsNotEmbedded`.** An invalid vector counts as a failed embedding: it is not stored, it raises `ScanEmbeddings.FailedCount`, and `FirstFailure` is an `InvalidEmbeddingException`. The #550 path that already exists then records `TextsNotEmbedded` for every detector that needed that text, and `ReportScanFailure` fires `OnDetectorFailure` once. There is no public API change, so this is `fix:`, 5.1.x.
- **Dimension: await the example vectors first.** The pipeline awaits the example phrases before it embeds the scan texts, and passes their dimension to `ScanEmbedder`. A wrong-length cached hit is re-embedded, and a wrong-length fresh vector fails only that text. The example vectors are memoized per generator, so this costs one extra sequential round trip, and only while the example cache is cold. `SemanticApprovalMatcher` already works this way.

## Approaches

- **A. Validate in `ScanEmbedder`, report through `FailedCount` (chosen).** One validation point for the pipeline and the approval matcher, and the reporting path already exists.
- **B. Validate in each detector at scoring time.** Rejected: a detector cannot raise the scan's `FailedCount`, so it would need a new reporting route. The bad vector would also still be cached.
- **C. A new `DetectorFailureKind.InvalidEmbedding`.** Rejected by Marcel: it is public API, so `feat:`. The `OnDetectorFailure` message already names `InvalidEmbeddingException` and its kind.
- **Dimension, rejected: compare after both finish.** No latency cost, but a stale wrong-length cached hit is never re-embedded, so it fails every scan until the cache is cleared. That is the persistence problem this issue is about.

## What changes

### `ScanEmbedder`

- `EmbedAsync` takes an `int? expectedDimension`. A vector is usable when `InvalidEmbeddingException.Problem` returns null and, when a dimension is given, its length matches.
- **Cached hits:** an unusable hit counts as a miss and is embedded again. A valid fresh vector overwrites it through `Set`. This also covers entries stored before this fix.
- **Fresh vectors, batch and per-input retry:** an unusable vector is not stored and not cached. Its text counts as failed, with `InvalidEmbeddingException(kind)` as the failure. The other vectors in the batch are still stored. An invalid vector is a bad answer for that input, not an outage, so it does not count towards `OutageFailures` and does not trigger a per-input retry of that text: the batch already answered for it.
- **Without an expected dimension** (my call): the first usable vector in the scan sets the dimension, and later ones must match it. That covers a caller that has no example dimension.
- `FirstFailure` keeps its rule: the batch exception first, otherwise the first single-input failure, which can now be an `InvalidEmbeddingException`.

### `DetectionPipeline.EmbedScanAsync`

- The example tasks run first, as they do now, and the pipeline awaits them before it starts the scan embedding. `EmbedExamplesAsync` also returns the example dimension of a detector that succeeded.
- The expected dimension is that of the first semantic detector whose examples embedded. When none did, no detector scores anything; the scan is still embedded without a dimension, so rule layers and failure reporting behave as today. (My call: in that case skipping the scan embedding would also be defensible, but it changes when `TextsNotEmbedded` versus `ExamplesNotEmbedded` is recorded, so it stays as is.)
- Cancellation and exception handling around `Task.WhenAll` keep their current shape: every task is still observed.

### `SemanticDetectorBase`

- **Standalone path, `GetEmbeddingsAsync`** (no pipeline scope): an unusable cached hit counts as a miss. Fresh vectors are checked against the example dimension before any of them is cached. One unusable vector throws `InvalidEmbeddingException` and nothing from that call is cached, as in `ExampleEmbedder`. The pipeline records it as `Threw`, which `DetectorFailureKind.Threw` already documents for the no-scope case.
- **Scoped path, `AnalyzeAsync(…, scan, …)`, a guard** (my call): a scan vector whose length differs from this detector's examples throws `InvalidEmbeddingException(DimensionMismatch)`, and so does one that `Problem` rejects. `ScanEmbedder` makes this unreachable when all detectors' examples share a dimension. It only fires if a provider returns different dimensions for different detectors' examples. It is recorded as `Threw`, which is visible, instead of scoring 0, which is silent.
- **Examples across tiers** (my call, adjacent gap): `ExampleEmbedder` checks one tier at a time, so High, Medium and Low could differ in length. `EmbedAllExamplesAsync` checks that all non-empty tiers share one dimension and throws `InvalidEmbeddingException(DimensionMismatch)` otherwise. That surfaces as `ExamplesNotEmbedded`.

### `SemanticApprovalMatcher`

- Passes `examples[0].Length` as the expected dimension. An invalid vector now leaves the cache alone, so the next call with the same arguments embeds again instead of failing forever. `Failed` keeps reporting the exception type name from `FirstFailure`. My call: when `FirstFailure` is an `InvalidEmbeddingException`, report its `Kind` instead, as the catch block already does. The existing checks in `Score` stay as a second line.

### Docs

- The XML remarks on `ScanEmbedder`, `ScanEmbeddings.FailedCount` and `DetectorFailureKind.TextsNotEmbedded` say that an unusable vector counts as a failed text.
- `website/docs`: wherever embedding caches or `TextsNotEmbedded` are described, add one sentence: an empty, zero-norm, non-finite or wrong-length vector is never cached and is reported as `TextsNotEmbedded`. The builder finds the page with grep.

## Tests

Use a fake generator that returns chosen vectors per input.

- **ScanEmbedder:** an empty, an all-zero, a NaN and a wrong-length fresh vector are each not cached and counted in `FailedCount`, with `InvalidEmbeddingException` of the right `Kind` as `FirstFailure`. Valid vectors in the same batch are still stored. An invalid cached hit is re-embedded and overwritten. An invalid batch vector does not trigger per-input retries, and does not count as an outage. Without an expected dimension, a mixed-length batch fails the odd ones out.
- **Pipeline:** a semantic detector whose only text gets a zero vector returns Clean with `TextsNotEmbedded` in `PipelineResult.Failures`, and `OnDetectorFailure` fires once. A second scan with a valid provider answer flags the text, which proves nothing bad was cached. A cached wrong-length vector from a persistent cache is re-embedded.
- **Standalone detector:** an invalid fresh vector throws `InvalidEmbeddingException` and caches nothing; an invalid cached hit is re-embedded.
- **Examples:** tiers of mixed length give `ExamplesNotEmbedded`.
- **Approvals:** an invalid call vector gives `Failed` with the kind, and the next call with a valid answer is scored, not failed.
- **Existing tests** that relied on a zero or wrong-length vector scoring Clean are changed to expect the failure, not deleted.

## Out of scope

- `DetectionPipeline` reading a thrown detector as Clean: #564.
- The hook CLIs' review timeout: #537.
