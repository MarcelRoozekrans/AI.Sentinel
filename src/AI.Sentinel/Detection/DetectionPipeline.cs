using System.Buffers;
using System.Text.RegularExpressions;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Detection;

public sealed class DetectionPipeline : IDetectionPipeline
{
    /// <summary>The id of the scan-limit finding. Owned by the pipeline, not by an <see cref="IDetector"/>.</summary>
    internal static readonly DetectorId ScanLimitId = new("SEC-00");

    private readonly IDetector[] _detectors;
    private readonly DetectorConfiguration?[] _configurations;
    private readonly IDetectionReviewer? _reviewer;
    private readonly ReviewLimits _reviewLimits;
    private readonly ILogger<DetectionPipeline>? _logger;
    private readonly Action<string>? _onDetectorFailure;
    private readonly bool _redactByDefault;
    private readonly EmbeddingScope? _embeddingScope;
    // The indices in _detectors of the semantic detectors, whose scan texts the pipeline embeds once for all of them.
    private readonly int[] _semanticIndices;

    internal DetectionPipeline(
        IEnumerable<IDetector> detectors,
        IReadOnlyDictionary<Type, DetectorConfiguration>? configurations,
        IDetectionReviewer? reviewer,
        ILogger<DetectionPipeline>? logger = null,
        Action<string>? onDetectorFailure = null,
        bool redactByDefault = true,
        EmbeddingScope? embeddingScope = null,
        ReviewLimits? reviewLimits = null)
    {
        var enabled = new List<IDetector>();
        var redactors = new List<IRedactingDetector>();
        var enabledConfigs = new List<DetectorConfiguration?>();
        foreach (var d in detectors)
        {
            DetectorConfiguration? cfg = null;
            if (configurations is not null)
            {
                configurations.TryGetValue(d.GetType(), out cfg);
            }

            if (!DetectorConfiguration.IsEnabled(d, cfg))
            {
                continue;  // skip disabled or not-opted-in detector entirely — zero CPU on the hot path
            }

            // AddAISentinel checks a pair that is set in full; only here, with the instance, is the
            // built-in value known that fills in a threshold left unset.
            if (d is SemanticDetectorBase semanticDetector)
            {
                semanticDetector.ThrowIfMediumAboveHigh(cfg);
                semanticDetector.ThrowIfReviewAboveMedium(cfg);
            }

            if (cfg?.Action == SentinelAction.Redact && d is not IRedactingDetector)
            {
                throw new InvalidOperationException(
                    $"AI.Sentinel: detector {d.GetType().Name} is configured with Action = Redact but does not implement IRedactingDetector. " +
                    "Only detectors that can locate their match can redact.");
            }

            enabled.Add(d);
            enabledConfigs.Add(cfg);
            if (d is IRedactingDetector redactor
                && (cfg?.Action ?? (redactByDefault ? SentinelAction.Redact : (SentinelAction?)null)) == SentinelAction.Redact)
            {
                redactors.Add(redactor);
            }
        }

        Redactors = redactors.ToArray();

        _detectors = enabled.ToArray();
        _configurations = enabledConfigs.ToArray();
        _reviewer = reviewer;
        _reviewLimits = reviewLimits ?? ReviewLimits.Default;
        _logger = logger;
        _onDetectorFailure = onDetectorFailure;
        _redactByDefault = redactByDefault;
        _embeddingScope = embeddingScope;

        var semanticIndices = new List<int>();
        for (var i = 0; i < _detectors.Length; i++)
        {
            if (_detectors[i] is SemanticDetectorBase) semanticIndices.Add(i);
        }
        _semanticIndices = semanticIndices.ToArray();
    }

    /// <inheritdoc />
    public IReadOnlyList<IRedactingDetector> Redactors { get; }

    private static int SeverityScore(Severity s) => s switch
    {
        Severity.Critical => 100,
        Severity.High => 70,
        Severity.Medium => 40,
        Severity.Low => 15,
        _ => 0
    };

    public async ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct)
    {
        if (_detectors.Length == 0)
        {
            return ctx.ExceedsScanBudget
                ? BuildResult([], ScanLimitFinding(ctx))
                : new PipelineResult(ThreatRiskScore.Zero, []);
        }

        var embedded = _embeddingScope is { } scope && _semanticIndices.Length > 0
            ? await EmbedScanAsync(scope, ctx, ct).ConfigureAwait(false)
            : null;

        // Each semantic detector's outcome, indexed like _detectors: its result plus its review candidate.
        var outcomes = new SemanticOutcome?[_detectors.Length];

        var results = await AnalyzeAllAsync(ctx, embedded, outcomes, ct).ConfigureAwait(false);

        // Floor/Cap before review, so candidacy uses the configured severity: a Cap below Medium keeps a rule-based
        // result out of review. The clamp skips clean results, so a Floor never makes a clean result a candidate.
        ApplySeverityClamp(results);

        // The severity each detector proposes before the semantic cap, None for a clean result. A review
        // step can lift a capped result back to it, so it is only needed when review is on.
        var reviewer = _reviewLimits.MaxPerScan > 0 ? _reviewer : null;
        var proposed = reviewer is not null ? ProposedSeverities(results) : null;

        ApplySemanticCap(results, outcomes);

        if (reviewer is not null && proposed is not null)
        {
            await ReviewAllAsync(reviewer, ctx, results, proposed, outcomes, ct).ConfigureAwait(false);
        }

        // After review: a verdict rebuilds the result, which would drop an override set earlier.
        ApplyActionOverrides(results);

        // Last, so no clamp, cap, review or action override touches it: the text was not scanned, which a
        // setting for one detector cannot undo.
        return BuildResult(results, ctx.ExceedsScanBudget ? ScanLimitFinding(ctx) : null);
    }

    private async ValueTask<DetectionResult[]> AnalyzeAllAsync(
        SentinelContext ctx, EmbeddedScan? embedded, SemanticOutcome?[] outcomes, CancellationToken ct)
    {
        var vTasks = ArrayPool<ValueTask<DetectionResult>>.Shared.Rent(_detectors.Length);
        DetectionResult[] results;
        try
        {
            // Start all detectors
            for (int i = 0; i < _detectors.Length; i++)
                vTasks[i] = SafeAnalyzeAsync(_detectors[i], _configurations[i], ctx, embedded, outcomes, i, ct);

            // Fast path: all completed synchronously (typical for rule-based detectors with cached clean results)
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

        return results;
    }

    private static DetectionResult ScanLimitFinding(SentinelContext ctx) =>
        DetectionResult.WithSeverity(ScanLimitId, Severity.Critical,
            $"New content is {ctx.NewContentBytes} bytes; only the first {ctx.MaxScanBytes} were scanned. Raise the scan budget (MaxScanBytes, SENTINEL_HOOK_MAX_SCAN_BYTES or SENTINEL_MCP_MAX_SCAN_BYTES) to scan more.");

    /// <summary>Runs one detector, degrading a failure to Clean, except a regex timeout, which is Critical.</summary>
    /// <remarks>
    /// A detector that reaches the network — any SemanticDetectorBase once an embedding endpoint is
    /// configured — can throw for reasons that have nothing to do with the content: the endpoint is
    /// down, the key expired, the provider rate-limited. Letting that escape aborts the whole scan. In
    /// the hook CLIs a thrown scan exits 1 on a prompt, which the host does not treat as a block, so the
    /// prompt would proceed unscanned by <em>every</em> detector, including the rule-based ones that never
    /// needed the network; on PreToolUse it blocks every tool call. One control being unavailable must not
    /// disable the rest, nor stop all work.
    /// <para>
    /// A <see cref="RegexMatchTimeoutException"/> is the exception to degrading: the content can provoke it, so
    /// passing it would let text through that no detector could judge. It becomes a Critical finding, which
    /// <c>SeverityCap</c> and <c>SeverityFloor</c> still apply to, but the semantic cap and review do not.
    /// </para>
    /// <para>
    /// A semantic detector gets this pipeline's configuration with the call, so its threshold overrides
    /// apply here and not in another named pipeline that shares the same detector instance. Its outcome, the result
    /// plus its review candidate, is recorded in <paramref name="outcomes"/> at <paramref name="index"/>.
    /// </para>
    /// </remarks>
    private async ValueTask<DetectionResult> SafeAnalyzeAsync(
        IDetector detector, DetectorConfiguration? configuration, SentinelContext ctx,
        EmbeddedScan? embedded, SemanticOutcome?[] outcomes, int index, CancellationToken ct)
    {
        try
        {
            if (detector is not SemanticDetectorBase semantic)
                return await detector.AnalyzeAsync(ctx, ct).ConfigureAwait(false);

            if (embedded is null)
                return Record(outcomes, index, await semantic.AnalyzeAsync(ctx, configuration, ct).ConfigureAwait(false));

            if (embedded.TextsFailures[index] is { } textsFailure)
            {
                // As without a scope: the rule layer still decides, and otherwise the failure is this detector's own.
                var rule = semantic.AnalyzeRuleLayer(ctx);
                if (!rule.IsClean) return RecordRuleLayer(outcomes, index, rule);
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(textsFailure);
            }

            // Its example phrases failed and were reported once for the scan; calling it would retry and report again.
            if (embedded.ExamplesFailed[index])
                return RecordRuleLayer(outcomes, index, semantic.AnalyzeRuleLayer(ctx));

            return Record(outcomes, index, await semantic.AnalyzeAsync(
                ctx, configuration, embedded.Scope, embedded.Scan, embedded.Texts[index], ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The caller asked to stop; that is not a detector fault. On a live token it is one, such as an
            // HttpClient timeout, and is reported below.
            throw;
        }
        catch (RegexMatchTimeoutException ex)
        {
            // Content can provoke this, unlike the faults below, so a pass would let text through that no one
            // could judge. outcomes[index] stays null: the semantic cap and review leave this result alone.
            var message = $"AI.Sentinel: detector {detector.Id.Value} timed out and was flagged Critical for this scan.";
            _logger?.LogWarning(ex, "AI.Sentinel: detector {DetectorId} timed out and was flagged Critical for this scan.", detector.Id.Value);
            _onDetectorFailure?.Invoke(message);
            return DetectionResult.WithSeverity(detector.Id, Severity.Critical,
                $"Regex timed out after {ex.MatchTimeout.TotalMilliseconds:0} ms; content could not be judged.");
        }
        catch (Exception ex)
        {
            var message = $"AI.Sentinel: detector {detector.Id.Value} failed and was skipped for this scan ({ex.GetType().Name}: {ex.Message}). Other detectors still ran.";
            _logger?.LogWarning(ex, "AI.Sentinel: detector {DetectorId} failed and was skipped for this scan.", detector.Id.Value);
            _onDetectorFailure?.Invoke(message);
            return DetectionResult.Clean(detector.Id);
        }
    }

    private static DetectionResult Record(SemanticOutcome?[] outcomes, int index, in SemanticOutcome outcome)
    {
        outcomes[index] = outcome;
        return outcome.Result;
    }

    /// <summary>Records a rule-layer result: a match came from the fast path, and neither has a review candidate.</summary>
    private static DetectionResult RecordRuleLayer(SemanticOutcome?[] outcomes, int index, DetectionResult result) =>
        Record(outcomes, index, new SemanticOutcome(result, Candidate: null, FromFastPath: !result.IsClean));

    /// <summary>The scan vectors every semantic detector shares, each detector's texts, and which detectors' text
    /// selection or example phrases failed.</summary>
    /// <param name="Texts">Each semantic detector's texts, collected once so it scores exactly what was embedded.
    /// Indexed like <c>_detectors</c>, as are <paramref name="TextsFailures"/> and <paramref name="ExamplesFailed"/>.</param>
    private sealed record EmbeddedScan(
        EmbeddingScope Scope, ScanEmbeddings Scan, IReadOnlyList<string>[] Texts, Exception?[] TextsFailures, bool[] ExamplesFailed);

    /// <summary>Embeds the distinct texts of every semantic detector once, and their example phrases, before the
    /// detectors run, and reports each kind of failure once for the scan.</summary>
    /// <remarks>Without this every semantic detector embedded its own texts, so one scan sent the same message to
    /// the provider once per detector, and a rejected input or an outage was reported by each of them.</remarks>
    private async Task<EmbeddedScan> EmbedScanAsync(EmbeddingScope scope, SentinelContext ctx, CancellationToken ct)
    {
        var union = new HashSet<string>(StringComparer.Ordinal);
        var detectorTexts = new IReadOnlyList<string>[_detectors.Length];
        var textsFailures = new Exception?[_detectors.Length];
        var exampleTasks = new Task<Exception?>[_semanticIndices.Length];
        for (var s = 0; s < _semanticIndices.Length; s++)
        {
            var semantic = (SemanticDetectorBase)_detectors[_semanticIndices[s]];
            IReadOnlyList<string> texts;
            try
            {
                texts = semantic.TextsToEmbed(ctx);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                // Reported by SafeAnalyzeAsync as this detector's failure, as when the detector selects its own texts.
                textsFailures[_semanticIndices[s]] = ex;
                texts = [];
            }

            // A detector whose rule layer will match still contributes its texts: the other semantic detectors
            // embed the same texts anyway, and keeping the rule check in the detector avoids running it twice.
            detectorTexts[_semanticIndices[s]] = texts;
            union.UnionWith(texts);

            // As before, a detector with nothing to score never embeds its example phrases.
            exampleTasks[s] = texts.Count > 0 ? EmbedExamplesAsync(semantic, scope, ct) : NoFailure;
        }

        var scanTask = union.Count > 0 ? EmbedTextsAsync(scope, union, ct) : Task.FromResult(ScanEmbeddings.Empty);

        // Awaits every task, so a cancellation or fault in one leaves none of the others unobserved.
        await Task.WhenAll([scanTask, .. exampleTasks]).ConfigureAwait(false);

        var scan = await scanTask.ConfigureAwait(false);
        ReportScanFailure(scan);

        var examplesFailed = new bool[_detectors.Length];
        var failedIds = new List<string>();
        Exception? firstExampleFailure = null;
        for (var s = 0; s < _semanticIndices.Length; s++)
        {
            if (await exampleTasks[s].ConfigureAwait(false) is not { } failure) continue;

            examplesFailed[_semanticIndices[s]] = true;
            failedIds.Add(_detectors[_semanticIndices[s]].Id.Value);
            firstExampleFailure ??= failure;
        }

        if (firstExampleFailure is not null) ReportExampleFailure(failedIds, firstExampleFailure);

        return new EmbeddedScan(scope, scan, detectorTexts, textsFailures, examplesFailed);
    }

    /// <summary>Reports the texts of <paramref name="scan"/> that could not be embedded, once for the scan.</summary>
    private void ReportScanFailure(ScanEmbeddings scan)
    {
        if (scan.FailedCount == 0) return;

        // ScanEmbeddings records a failure with every failed text.
        var ex = scan.FirstFailure!;
        var message = $"AI.Sentinel: {scan.FailedCount} of {scan.TotalCount} texts could not be embedded and were skipped for this scan ({ex.GetType().Name}: {ex.Message}). Other texts and detectors still ran.";
        _logger?.LogWarning(ex, "AI.Sentinel: {Failed} of {Total} texts could not be embedded and were skipped for this scan ({ExType}: {ExMessage}). Other texts and detectors still ran.",
            scan.FailedCount, scan.TotalCount, ex.GetType().Name, ex.Message);
        _onDetectorFailure?.Invoke(message);
    }

    /// <summary>Reports the detectors whose example phrases could not be embedded, once for the scan.</summary>
    private void ReportExampleFailure(List<string> detectorIds, Exception ex)
    {
        var ids = string.Join(", ", detectorIds);
        var message = $"AI.Sentinel: the example phrases of detector(s) {ids} could not be embedded, so they were skipped for this scan ({ex.GetType().Name}: {ex.Message}). Other detectors still ran.";
        _logger?.LogWarning(ex, "AI.Sentinel: the example phrases of detector(s) {DetectorIds} could not be embedded, so they were skipped for this scan ({ExType}: {ExMessage}). Other detectors still ran.",
            ids, ex.GetType().Name, ex.Message);
        _onDetectorFailure?.Invoke(message);
    }

    private static readonly Task<Exception?> NoFailure = Task.FromResult<Exception?>(null);

    /// <summary>The failure of <paramref name="semantic"/>'s example phrases, or <see langword="null"/>.</summary>
    private static async Task<Exception?> EmbedExamplesAsync(SemanticDetectorBase semantic, EmbeddingScope scope, CancellationToken ct)
    {
        try
        {
            await semantic.GetExampleVectorsAsync(scope.Generator, scope.ExampleCache, ct).ConfigureAwait(false);
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // On a live token an OperationCanceledException is a provider failure, such as an HttpClient timeout.
            // A provider also often surfaces a cancellation as its own exception type; cancellation wins.
            ct.ThrowIfCancellationRequested();
            return ex;
        }
    }

    /// <summary>The scan vectors of <paramref name="texts"/>. A fault outside the provider calls, which the embedder
    /// already isolates, such as a throwing scan cache, counts as every text failing.</summary>
    private static async Task<ScanEmbeddings> EmbedTextsAsync(EmbeddingScope scope, HashSet<string> texts, CancellationToken ct)
    {
        try
        {
            return await ScanEmbedder.EmbedAsync(scope, texts, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            ct.ThrowIfCancellationRequested();
            return new ScanEmbeddings(new Dictionary<string, ReadOnlyMemory<float>>(StringComparer.Ordinal), texts.Count, texts.Count, ex);
        }
    }

    /// <summary>One detection the review step may send to the reviewer.</summary>
    /// <param name="Index">The detector's index in <c>_detectors</c>.</param>
    /// <param name="Request">What the reviewer is asked.</param>
    /// <param name="RuleBased">True for an <see cref="ILlmEscalatingDetector"/>, which ranks before a semantic
    /// candidate of the same proposed severity.</param>
    /// <param name="Reason">The detector's own reason, before the semantic cap; empty for a text that reached no
    /// bucket. A verdict keeps it in front of the review's outcome.</param>
    private sealed record Candidate(int Index, ReviewRequest Request, bool RuleBased, string Reason);

    /// <summary>How one review ended before its verdict is applied.</summary>
    private enum ReviewStatus { Answered, Failed, TimedOut }

    /// <summary>The longest reviewer reason kept in a result's reason.</summary>
    private const int MaxReviewReasonLength = 200;

    /// <summary>Sends the top-ranked review candidates to <paramref name="reviewer"/> concurrently, each under the
    /// review timeout, and applies their verdicts.</summary>
    /// <remarks>
    /// The candidates are the semantic results that did not come from the fast path and either propose Medium or
    /// higher or have a text at or above the review threshold, and the Medium-or-higher results of an
    /// <see cref="ILlmEscalatingDetector"/>. A configured <see cref="DetectorConfiguration.SeverityCap"/> below
    /// Medium keeps a bucket result at or above Medium out. They are ranked by proposed severity, then rule-based
    /// first, then by score, and the first <see cref="ReviewLimits.MaxPerScan"/> are reviewed; the rest keep their
    /// shown result. A review that fails or times out keeps the shown result too, and a scan with any such review
    /// reports one warning. The caller's cancellation is rethrown.
    /// </remarks>
    private async Task ReviewAllAsync(
        IDetectionReviewer reviewer, SentinelContext ctx, DetectionResult[] results, Severity[] proposed,
        SemanticOutcome?[] outcomes, CancellationToken ct)
    {
        var candidates = CollectCandidates(ctx, results, proposed, outcomes);
        if (candidates.Count == 0) return;

        candidates.Sort(CompareCandidates);

        var reviewed = Math.Min(candidates.Count, _reviewLimits.MaxPerScan);
        for (var c = reviewed; c < candidates.Count; c++)
            CountReview(ReviewOutcomes.OverBudget, candidates[c].Request.DetectorId);

        var reviews = new Task<(ReviewStatus Status, ReviewVerdict? Verdict, Exception? Failure)>[reviewed];
        for (var c = 0; c < reviewed; c++)
            reviews[c] = ReviewOneAsync(reviewer, candidates[c].Request, ct);

        // Awaits every review, so a cancellation in one leaves none of the others unobserved.
        await Task.WhenAll(reviews).ConfigureAwait(false);

        var failed = 0;
        Exception? firstFailure = null;
        for (var c = 0; c < reviewed; c++)
        {
            var (status, verdict, failure) = await reviews[c].ConfigureAwait(false);
            var candidate = candidates[c];
            if (status != ReviewStatus.Answered)
            {
                failed++;
                firstFailure ??= failure;
                CountReview(status == ReviewStatus.TimedOut ? ReviewOutcomes.TimedOut : ReviewOutcomes.Failed, candidate.Request.DetectorId);
                continue;
            }

            CountReview(ApplyVerdict(results, candidate, verdict), candidate.Request.DetectorId);
        }

        if (failed > 0) ReportReviewFailures(failed, reviewed, firstFailure);

        // A verdict may move a severity in either direction: hold it to the configured floor and cap again.
        ApplySeverityClamp(results);
    }

    /// <summary>The review candidates of this scan, unranked.</summary>
    private List<Candidate> CollectCandidates(
        SentinelContext ctx, DetectionResult[] results, Severity[] proposed, SemanticOutcome?[] outcomes)
    {
        var candidates = new List<Candidate>();
        for (var i = 0; i < _detectors.Length; i++)
        {
            var cfg = _configurations[i];
            var cap = cfg?.SeverityCap;
            if (_detectors[i] is SemanticDetectorBase semantic)
            {
                if (outcomes[i] is not { FromFastPath: false, Candidate: { } found } outcome) continue;
                if (proposed[i] < Severity.Medium && found.Score < semantic.EffectiveReviewThreshold(cfg)) continue;

                // A cap below Medium means the pipeline does not want this detector above it: only a text that
                // reached no bucket is reviewed, and its verdict is held to the cap.
                if (cap < Severity.Medium && !outcome.Result.IsClean) continue;

                // The highest bucket severity, raised to a configured floor, then limited by a configured cap.
                var maximum = cfg?.SeverityFloor is { } floor && floor > semantic.MaximumBucketSeverity
                    ? floor
                    : semantic.MaximumBucketSeverity;

                // The outcome holds the result before the semantic cap, so its reason is the bucket's.
                candidates.Add(new Candidate(i, new ReviewRequest(
                    semantic.Id, semantic.Criterion, found.Text, found.Role, found.Score, proposed[i],
                    Limit(maximum, cap)), RuleBased: false, outcome.Result.Reason));
            }
            else if (_detectors[i] is ILlmEscalatingDetector escalating && proposed[i] >= Severity.Medium)
            {
                // A rule-based detector does not report which text matched: the newest message's detection text is
                // shown, so a flagged tool call or result is seen, not an empty text.
                var newest = ctx.Messages.Count > 0 ? ctx.Messages[^1] : null;
                candidates.Add(new Candidate(i, new ReviewRequest(
                    escalating.Id, escalating.ReviewCriterion,
                    newest is null ? string.Empty : SentinelContext.MessageText(newest), newest?.Role, Score: null,
                    proposed[i], Limit(Severity.Critical, cap)), RuleBased: true, results[i].Reason));
            }
        }

        return candidates;
    }

    private static Severity Limit(Severity severity, Severity? cap) => cap is { } c && severity > c ? c : severity;

    /// <summary>Proposed severity, highest first; then rule-based before semantic; then score, highest first; then
    /// detector order, so the ranking is stable.</summary>
    private static int CompareCandidates(Candidate a, Candidate b)
    {
        var bySeverity = b.Request.ProposedSeverity.CompareTo(a.Request.ProposedSeverity);
        if (bySeverity != 0) return bySeverity;
        if (a.RuleBased != b.RuleBased) return a.RuleBased ? -1 : 1;
        var byScore = (b.Request.Score ?? 0f).CompareTo(a.Request.Score ?? 0f);
        return byScore != 0 ? byScore : a.Index.CompareTo(b.Index);
    }

    /// <summary>One review under the review timeout, timed by <see cref="ReviewLimits.TimeProvider"/>. A reviewer
    /// still running at the timeout is abandoned: its token is cancelled and a later fault observed. Only the caller's
    /// cancellation escapes, and it wins over any failure or timeout seen at the same time.</summary>
    private async Task<(ReviewStatus Status, ReviewVerdict? Verdict, Exception? Failure)> ReviewOneAsync(
        IDetectionReviewer reviewer, ReviewRequest request, CancellationToken ct)
    {
        // The reviewer's token: the caller's cancellation, and the timeout once the review is abandoned.
        var reviewCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var abandoned = false;
        try
        {
            // Inside the try: a reviewer may throw before it returns a task.
            var review = reviewer.ReviewAsync(request, reviewCts.Token).AsTask();

            // A review abandoned at the timeout may still fault; observe it so it is not an unobserved task exception.
            _ = review.ContinueWith(
                static t => _ = t.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);

            var verdict = await review.WaitAsync(_reviewLimits.Timeout, _reviewLimits.TimeProvider, ct).ConfigureAwait(false);
            return (ReviewStatus.Answered, verdict, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A reviewer often surfaces the caller's cancellation as its own exception type, a timeout among them;
            // cancellation wins.
            ct.ThrowIfCancellationRequested();
            if (ex is not TimeoutException) return (ReviewStatus.Failed, null, ex);

            abandoned = true;
            Abandon(reviewCts, ex);
            return (ReviewStatus.TimedOut, null, ex);
        }
        finally
        {
            // An abandoned review's source is disposed once its cancellation callbacks have run.
            if (!abandoned) reviewCts.Dispose();
        }
    }

    /// <summary>Cancels the token of a review abandoned at the timeout, so a reviewer that watches it learns to stop,
    /// and disposes the source once that is done.</summary>
    /// <remarks>The reviewer's own cancellation callbacks run off the scan thread, so one that blocks cannot stall the
    /// scan. One that throws is logged with <paramref name="timeout"/>, as one failure; it must not turn the timeout
    /// into a failed scan, and it is not known yet when the scan reports its review failures.</remarks>
    private void Abandon(CancellationTokenSource source, Exception timeout)
    {
        _ = source.CancelAsync().ContinueWith(
            static (cancelling, state) =>
            {
                var (source, pipeline, timeout) = ((CancellationTokenSource, DetectionPipeline, Exception))state!;
                source.Dispose();
                if (cancelling.Exception is { } callbackFailure)
                    pipeline.ReportCancellationCallbackFailure(new AggregateException(timeout, callbackFailure.Flatten()));
            },
            (source, this, timeout),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    /// <summary>Logs a reviewer cancellation callback that threw after its review timed out.</summary>
    private void ReportCancellationCallbackFailure(AggregateException failure) =>
        _logger?.LogWarning(failure, "AI.Sentinel: a reviewer's cancellation callback threw after its review timed out; the detection kept its capped severity.");

    /// <summary>Applies <paramref name="verdict"/> to the candidate's result and returns the <c>outcome</c> tag.</summary>
    /// <remarks>No verdict keeps the shown result. A verdict above the request's maximum is held to it. None clears
    /// the result; any other verdict sets that severity, so confirming the proposed severity lifts the semantic cap.
    /// The new reason keeps the detector's own reason, then names the outcome and the reviewer's reason.</remarks>
    private static string ApplyVerdict(DetectionResult[] results, Candidate candidate, ReviewVerdict? verdict)
    {
        if (verdict?.Severity is not { } severity) return ReviewOutcomes.NoVerdict;

        var request = candidate.Request;
        if (severity > request.MaximumSeverity) severity = request.MaximumSeverity;

        if (severity == Severity.None)
        {
            results[candidate.Index] = DetectionResult.Clean(request.DetectorId);
            return ReviewOutcomes.Cleared;
        }

        var outcome = severity == request.ProposedSeverity ? ReviewOutcomes.Confirmed
            : severity > request.ProposedSeverity ? ReviewOutcomes.Raised
            : ReviewOutcomes.Lowered;
        var reason = SemanticDetectorBase.Sanitise(verdict.Reason ?? string.Empty, MaxReviewReasonLength);
        var reviewed = reason.Length == 0 ? $"Reviewed: {outcome}" : $"Reviewed: {outcome} — {reason}";
        results[candidate.Index] = DetectionResult.WithSeverity(request.DetectorId, severity,
            candidate.Reason.Length == 0 ? reviewed : $"{candidate.Reason} — {reviewed}");
        return outcome;
    }

    private static void CountReview(string outcome, DetectorId detector) =>
        SentinelMetrics.Reviews.Add(1,
            new KeyValuePair<string, object?>("outcome", outcome),
            new KeyValuePair<string, object?>("detector", detector.Value));

    /// <summary>Reports the reviews that failed or timed out, once for the scan.</summary>
    private void ReportReviewFailures(int failed, int reviewed, Exception? firstFailure)
    {
        var message = $"AI.Sentinel: {failed} of {reviewed} reviews failed or timed out; those detections keep their capped severity.";
        _logger?.LogWarning(firstFailure, "AI.Sentinel: {Failed} of {Reviewed} reviews failed or timed out; those detections keep their capped severity.",
            failed, reviewed);
        _onDetectorFailure?.Invoke(message);
    }

    private static Severity[] ProposedSeverities(DetectionResult[] results)
    {
        var proposed = new Severity[results.Length];
        for (int i = 0; i < results.Length; i++)
            proposed[i] = results[i].IsClean ? Severity.None : results[i].Severity;
        return proposed;
    }

    /// <summary>The severity a semantic detector's embedding result is capped at without a reviewer verdict.</summary>
    private const Severity SemanticCap = Severity.Medium;

    /// <summary>Caps each semantic detector's embedding result at <see cref="SemanticCap"/>, or at its configured
    /// <see cref="DetectorConfiguration.SeverityFloor"/> when that is higher.</summary>
    /// <remarks>A regex fast-path match is never capped, nor is a detector configured with
    /// <see cref="DetectorConfiguration.CapSemanticSeverity"/> false. A floor above the cap raises the cap level to the
    /// floor, it does not remove the cap: the shown severity is the lower of the proposed severity and the higher of
    /// Medium and the floor.</remarks>
    private void ApplySemanticCap(DetectionResult[] results, SemanticOutcome?[] outcomes)
    {
        for (int i = 0; i < results.Length; i++)
        {
            if (outcomes[i] is not { FromFastPath: false }) continue;

            var cfg = _configurations[i];
            if (cfg?.CapSemanticSeverity == false) continue;

            var level = cfg?.SeverityFloor is { } floor && floor > SemanticCap ? floor : SemanticCap;
            if (results[i].Severity <= level) continue;

            results[i] = results[i] with
            {
                Severity = level,
                Reason = $"Semantic match — capped at {level} pending review",
            };
        }
    }

    private void ApplySeverityClamp(DetectionResult[] results)
    {
        for (int i = 0; i < results.Length; i++)
        {
            var cfg = _configurations[i];
            if (cfg is null || results[i].IsClean) continue;

            var clamped = results[i].Severity;
            if (cfg.SeverityFloor is { } floor && clamped < floor) clamped = floor;
            if (cfg.SeverityCap is { } cap && clamped > cap) clamped = cap;

            if (clamped != results[i].Severity)
            {
                results[i] = results[i] with { Severity = clamped };
            }
        }
    }

    private void ApplyActionOverrides(DetectionResult[] results)
    {
        for (int i = 0; i < results.Length; i++)
        {
            if (results[i].IsClean) continue;

            var action = _configurations[i]?.Action
                ?? (_detectors[i] is IRedactingDetector && _redactByDefault ? SentinelAction.Redact : (SentinelAction?)null);
            if (action is not null)
            {
                results[i] = results[i] with { ActionOverride = action };
            }
        }
    }

    private static bool AllCompletedSuccessfully(ValueTask<DetectionResult>[] tasks, int count)
    {
        foreach (ref readonly var t in tasks.AsSpan(0, count))
            if (!t.IsCompletedSuccessfully) return false;
        return true;
    }

    private static PipelineResult BuildResult(DetectionResult[] results, DetectionResult? scanLimit = null)
    {
        var nonClean = new List<DetectionResult>();
        var scores = new ThreatRiskScore[results.Length + (scanLimit is null ? 0 : 1)];
        for (int i = 0; i < results.Length; i++)
        {
            if (!results[i].IsClean) nonClean.Add(results[i]);
            scores[i] = new ThreatRiskScore(SeverityScore(results[i].Severity));
        }

        if (scanLimit is not null)
        {
            nonClean.Add(scanLimit);
            scores[^1] = new ThreatRiskScore(SeverityScore(scanLimit.Severity));
        }
        var score = ThreatRiskScore.Aggregate(scores);
        return new PipelineResult(score, nonClean);
    }
}
