# Embed once per scan, per pipeline (#435, #508)

## Why

**#435.** A scan with every semantic detector enabled embeds the same text about 40 times, once per detector:

- Each detector checks its own scan cache, finds nothing and calls the generator.
- A cache is created per detector when `SentinelOptions.EmbeddingCache` is unset.
- A shared `EmbeddingCache` does not help either: the detectors run concurrently through `Task.WhenAll`, so every miss happens before the first `Set`.

On a hosted embedding endpoint this costs 40 round-trips and 40 times the tokens on every message, and it invites rate limiting. Failures are also too coarse: one input the provider rejects, for example one over the token limit, fails the whole `GenerateAsync` call, and `DetectionPipeline.SafeAnalyzeAsync` turns that into Clean for the whole detector, hiding every other message in the scan.

**#508.** A named pipeline accepts `EmbeddingGenerator`, `EmbeddingCache` and `ExampleEmbeddingCache` and never uses them. The detectors are shared singletons built from the default pipeline's options, so every pipeline embeds with the default's generator. Marcel decided that a generator per pipeline should work, rather than the setting being rejected.

Both issues have the same cause: the generator and caches are fixed per detector instance, while they belong to the pipeline running the scan. Moving them to the pipeline fixes both.

## Goals

1. **One embedding per text per scan.** A scan embeds each distinct text at most once, in at most one batch call when nothing fails, however many semantic detectors are enabled.
2. **A named pipeline uses its own generator and caches** when it sets them, following the inheritance rule below.
3. **Per-input failure isolation.** An input the generator rejects only loses its own vector. The other texts of the scan are still scored, and the other detectors are unaffected.
4. **Example phrases are embedded once per generator**, with concurrent first scans sharing one in-flight embedding: single-flight.
5. **Scores do not change.** The same texts are scored against the same vectors with the same math. The ComplianceEval numbers must be identical before and after.

## Non-goals

- Keyed embedding generators from the container per pipeline name, such as `AddKeyedSingleton<IEmbeddingGenerator<…>>(name)`. That would be new API; a named pipeline sets `SentinelOptions.EmbeddingGenerator` directly.
- Changes to the public `IDetector`, `IEmbeddingCache` or `SentinelContext` API.
- Root-causing the unconfirmed 30 s hang on the first screening reported in a #435 comment. Single-flight removes the obvious suspect, many concurrent first-use example embeddings. If the hang still reproduces after this change, it is traced separately.
- The #511 escalation and judge work: Wave 3.

## Anti-goals

These would make the change a failure even if the tests pass:

- **Any change to a score or severity for the same input and generator.**
- **Vectors from one generator compared against vectors from another.** For example, a named pipeline with its own model reading the default pipeline's example cache. That gives wrong scores silently.
- **A breaking change for third-party semantic detectors** built on `SemanticDetectorBase` and run outside a pipeline, such as in Detectors.Sdk tests or hosts that call `AnalyzeAsync` directly.
- **A failure that is quieter than today.** A failed embedding must still reach the logger and `OnDetectorFailure`.

## Decisions

### Decided by Marcel

**D1. Detector input.** The pipeline passes an internal *embedding scope* to each semantic detector through the existing internal overload, extended to `SemanticDetectorBase.AnalyzeAsync(ctx, configuration, scope, ct)`. This overload already carries the pipeline's thresholds. `SentinelContext` gains no embedding state.

The public `AnalyzeAsync(ctx, ct)` keeps today's behaviour exactly: it uses the generator and caches of the `SentinelOptions` passed to the detector's constructor.

**D2. Inheritance: generator and caches move as one unit.** For a named pipeline:

| Named pipeline sets | Generator | Scan cache | Example cache |
|---|---|---|---|
| a generator | its own | its own if set, otherwise a fresh in-memory cache | its own if set, otherwise none |
| no generator | the default pipeline's resolved generator | its own if set, otherwise the default's | its own if set, otherwise the default's |

"The default pipeline's resolved generator" means after `WithEmbeddingGeneratorFromServices`: set explicitly, or taken from the container. A named pipeline never uses the default's caches with a generator other than the default's.

### Builder's calls, proposed in the brainstorm without objection

**C1. Named pipeline and the container.** A named pipeline's own `UseEmbeddingGeneratorFromServices` does not add a separate container lookup. Without its own generator it inherits the default's resolved generator, which already includes a container-registered one when the default allows that.

**C2. Example vectors are cached in process per generator instance**, compared by reference. A `ConditionalWeakTable` keyed by the generator lets a disposed generator and its vectors be collected. Two pipelines sharing a generator embed the example phrases once; two different generators never mix.

`EmbeddingGeneratorMetadata` is not a safe key: two clients for the same model ID can differ in dimensions or endpoint.

**C3. Single-flight for example phrases.** The first use of a (generator, detector) pair runs as one shared task that concurrent scans await. A task that fails or is cancelled is not kept, so the next scan retries; a cancelled first caller must not poison the entry for others.

The shared task runs on the first caller's token. On `OperationCanceledException` the entry is evicted. A waiter that did not itself cancel retries once with its own token, starting a fresh task. A waiter whose own token is cancelled propagates the cancellation.

Within that task the existing persistent `ExampleEmbeddingCache` path stays: embed only what the cache misses, check that the counts match one-to-one, and `Set` each miss.

**C4. Failure reporting once per scan.** A failed input is reported once per scan through the pipeline's logger and `OnDetectorFailure`, not once per detector that wanted it. The message names how many inputs failed and the exception type and message, never the input text, which may be sensitive.

A detector that wanted the failed input scores its other texts. A detector left with no vectors returns Clean, as an unavailable control does today.

**C4a. Example-phrase failures are reported once per scan too.** If the single-flight example task fails, the pipeline reports it once per scan with the same shape as C4, instead of once per detector that awaited it. Today that path logs about 40 near-identical warnings.

**C5. The inert-semantic warning is judged per pipeline on its effective generator**, per D2. A named pipeline that sets its own generator is no longer reported inert. The hint "A generator set on a named pipeline's options is not used, because the detectors are shared with the default pipeline" is removed, and the named-pipeline hint points at setting `EmbeddingGenerator` on that pipeline or on the default.

## How it works

### The embedding scope

There is one internal scope per pipeline. It holds:
- the resolved generator,
- the scan cache, which is never null: the configured cache, or one fresh `InMemoryLruEmbeddingCache` per pipeline,
- the optional example cache.

"The default's" in D2 means the same instance. The default pipeline's scope is built once per service provider from the resolved default `SentinelOptions` singleton, never by resolving the container's generator again, so the generator is reference-equal to the one the detectors were constructed with (C2). A named pipeline that inherits shares that scope's cache objects; the fresh in-memory scan cache of the default scope is shared too.

`BuildDetectionPipeline` resolves the scope from the pipeline's options per D2 and passes it to the `DetectionPipeline` constructor. Without a generator there is no scope, and semantic detectors run their rule layer only, as today.

A `DetectionPipeline` constructed without a scope, as the tests do through the internal constructor, calls semantic detectors exactly as today, through the overload without a scope. They then fall back to their constructor options.

### A scan

In `DetectionPipeline.RunAsync`, before the detectors start, and only when the pipeline has a scope and at least one enabled `SemanticDetectorBase`:

1. **Collect the texts.** Ask each enabled semantic detector for the texts it will score, through an internal method that wraps today's `SelectTextsToScore`, with placeholders normalised, blanks and duplicates dropped, and the 16-text fold. The legacy `GetText` blank opt-out is honoured: such a detector contributes nothing.

   A detector whose rule layer will match also contributes its texts. Precomputing them is cheap now that they are shared, and keeping the rule check in the detector avoids duplicating it.
2. **Union and look up.** Merge the texts of all detectors, dropping duplicates with an ordinal comparison, and look each one up in the scope's scan cache.
3. **Embed the misses in one batch** with `GenerateAsync`.
   - If the counts don't match one-to-one, treat it as a batch failure.
   - On a batch failure other than cancellation, retry each missing input on its own with one `GenerateAsync` call per input, run sequentially to avoid a burst against a provider that may be rate limiting.
   - An input whose own call fails is recorded as failed.
   - **Outage cut-off (decided by Marcel, D3).** If the first two single-input calls both fail and none has succeeded, the endpoint is treated as down and every remaining input is recorded as failed without a call. An outage, 401 or 429 then costs at most two extra calls. If the first two inputs are both genuinely bad, that scan behaves as it does today.
   - With only one missing input there is no retry: the batch failure is that input's failure.
   - Successful vectors are `Set` in the scan cache.
4. **Build the scan's vector map** (text → vector) and pass it, with the scope, to each semantic detector through the internal overload.
5. **Score in the detector.** The detector awaits its single-flight example vectors for the scope's generator, then looks its texts up in the map. A text missing from the map is skipped. If at least one input failed, the pipeline reports it once (C4).

A detector called with a scope never calls the generator for scan texts itself. It calls it only through the single-flight example task.

**Cancellation** propagates from every step as `OperationCanceledException`, as it does today.

**Ordering.** Precomputing runs before rule-based detectors start. Their results do not depend on it, so starting them first would only shorten wall-clock time. That is the builder's call: if the rule-based detectors start immediately and the semantic ones await the shared embedding task, then sequencing is free to optimise. Correctness does not depend on it.

### Example phrases

`SemanticDetectorBase` replaces `_highVectors`, `_mediumVectors`, `_lowVectors` and `_initLock` with a per-generator store (C2, C3) that maps generator → shared `Task` of the three bucket arrays.

The public path, with the constructor's generator, uses the same store, so a detector used both in and outside a pipeline with the same generator embeds its examples once.

## Testing

- **The fan-out test that matters.** An async fake generator that yields (`await Task.Delay(1)`) and counts inputs per call. A scan through a pipeline with several semantic detectors and two messages must embed each distinct text exactly once, in one call. A synchronous fake would hide the concurrent fan-out, so it does not count as evidence.
- **Per-input isolation.** A fake that throws on any batch containing a marked input and on that input alone. The other texts of the scan are still scored and can still raise a detection, and the failure is reported exactly once per scan.
- **Outage cut-off.** A fake that always throws: a scan with many texts makes exactly the batch call plus two single calls, and reports once.
- **Count mismatch** is handled as a batch failure, falling back to one input at a time.
- **#508.** Two named pipelines with two different fake generators: each scan uses only its own pipeline's generator, for both scan texts and examples. A named pipeline without a generator uses the default's. A named pipeline with its own generator does not read or write the default's scan cache or example cache.
- **Single-flight.** Many concurrent first scans call the generator for the example phrases once per (generator, detector). A failed first attempt is retried on the next scan, and a cancelled first caller does not fail the others.
- **Public path unchanged.** `AnalyzeAsync(ctx, ct)` on a standalone detector still embeds with its constructor options. The existing semantic tests stay green unchanged.
- **Inert warning.** A named pipeline with its own generator gives no warning; the reworded hint is covered.
- **Scores.** ComplianceEval output before and after is identical, compared as the full report rather than a summary.

Run the tests without the AOT publish:
`dotnet test tests/AI.Sentinel.Tests --filter-not-class "*DetectorRegistrationTrimTests"` (SDK 10.0.403).

## Docs

- Update the `SemanticDetectorBase` remarks and the semantic-detection and named-pipeline docs:
  - one embedding per text per scan;
  - per-pipeline generator and caches, with the D2 table;
  - per-input failure handling.
- Remove any statement that a named pipeline's generator is ignored.

## Left to the builder

- The names and shape of the internal scope and vector-map types.
- Whether the pipeline starts rule-based detectors before the shared embedding finishes.
- How the per-generator example store is laid out internally, as long as C2 and C3 hold.
