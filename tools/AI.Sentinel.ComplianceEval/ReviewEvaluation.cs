using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.ComplianceEval;

/// <summary>Scores the held-out phrases through an internal <see cref="DetectionPipeline"/> over one detector, in three
/// configurations: embeddings alone and uncapped, embeddings capped at Medium, and embeddings plus a reviewer. A
/// separate full-pipeline pass runs every evaluated detector together to measure the review budget.</summary>
/// <remarks>Configuration 1 is today's behaviour, and its verdict is the one the tool's exit code guards through the
/// direct <c>AnalyzeAsync</c> path. Nothing here fails the run: judge output is not deterministic.</remarks>
internal sealed class ReviewEvaluation(
    EmbeddingScope scope, IDetectionReviewer? reviewer, bool toolMessages, CancellationToken ct)
{
    private static readonly string[] ConfigurationNames =
    [
        "1. Embeddings alone, uncapped",
        "2. Embeddings capped at Medium",
        "3. Embeddings plus judge",
    ];

    /// <summary>Legitimate requests that reached High in configuration 3, reported but never failing the run.</summary>
    public List<string> JudgedHighs { get; } = [];

    /// <summary>The p-th percentile of <paramref name="values"/> by linear interpolation, or 0 when there are none.</summary>
    /// <param name="values">The samples, in any order.</param>
    /// <param name="p">The fraction, from 0 to 1; 0.5 is the median.</param>
    internal static double Percentile(IReadOnlyList<double> values, double p)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count == 0) return 0;
        var sorted = values.OrderBy(v => v).ToArray();
        var position = p * (sorted.Length - 1);
        var lower = (int)Math.Floor(position);
        var upper = (int)Math.Ceiling(position);
        return sorted[lower] + ((sorted[upper] - sorted[lower]) * (position - lower));
    }

    /// <summary>Checks <see cref="Percentile"/> on three cases, since the tool has no test project.</summary>
    /// <exception cref="InvalidOperationException">A case gave the wrong value.</exception>
    internal static void SelfCheck()
    {
        if (Percentile([], 0.95) != 0 || Percentile([7], 0.95) != 7 || Math.Abs(Percentile([1, 2, 3, 4], 0.5) - 2.5) > 1e-9)
        {
            throw new InvalidOperationException("ReviewEvaluation.Percentile self-check failed.");
        }
    }

    /// <summary>Evaluates <paramref name="detector"/> on the held-out subset of <paramref name="phrases"/>.</summary>
    /// <returns>The "Held-out review" Markdown section for the detector.</returns>
    public async Task<string> EvaluateAsync(SemanticDetectorBase detector, Phrase[] phrases)
    {
        ArgumentNullException.ThrowIfNull(detector);
        var id = detector.Id.Value;
        var heldOut = phrases
            .Where(p => p.IsHeldOut && (!p.IsPositive || string.Equals(p.Detector, id, StringComparison.Ordinal)))
            .ToArray();

        var section = new StringBuilder();
        section.AppendLine(CultureInfo.InvariantCulture, $"### Held-out review: {id}");
        section.AppendLine();
        // No configuration below sets a ReviewThreshold, so the detector's built-in one is the effective one.
        section.AppendLine(CultureInfo.InvariantCulture,
            $"Review threshold: {detector.EvaluationReviewThreshold:0.00}; Low threshold: {detector.EvaluationLowThreshold:0.00}.");
        section.AppendLine();
        var positives = heldOut.Count(p => p.IsPositive);
        var benign = heldOut.Length - positives;
        if (heldOut.Length == 0)
        {
            section.AppendLine("No held-out phrases for this detector yet: every phrase is `fit`, so there is nothing to report.");
            section.AppendLine();
            return section.ToString();
        }

        section.AppendLine(CultureInfo.InvariantCulture, $"{positives} held-out positives, {benign} held-out benign texts.");
        section.AppendLine();
        section.AppendLine("| Config | Positives >= High | Positives >= Medium | Benign >= High | Benign >= Medium | p50 added ms | p95 added ms | Candidates per detector-scan |");
        section.AppendLine("|---|---|---|---|---|---|---|---|");

        var configurations = new[]
        {
            Pipeline(detector, capped: false, withReviewer: false),
            Pipeline(detector, capped: true, withReviewer: false),
            reviewer is null ? null : Pipeline(detector, capped: true, withReviewer: true),
        };

        var baseline = new Dictionary<string, double>(StringComparer.Ordinal);
        for (var c = 0; c < configurations.Length; c++)
        {
            if (configurations[c] is not { } pipeline)
            {
                section.AppendLine(CultureInfo.InvariantCulture,
                    $"| {ConfigurationNames[c]} | skipped | skipped | skipped | skipped | skipped | skipped | skipped |");
                continue;
            }

            section.AppendLine(await RunConfigurationAsync(c, pipeline, detector, heldOut, baseline).ConfigureAwait(false));
        }

        section.AppendLine();
        foreach (var note in _notes) section.AppendLine(note).AppendLine();
        _notes = [];
        return section.ToString();
    }

    private async Task<string> RunConfigurationAsync(
        int configuration, DetectionPipeline pipeline, SemanticDetectorBase detector, Phrase[] heldOut, Dictionary<string, double> baseline)
    {
        var id = detector.Id.Value;
        int positiveHigh = 0, positiveMedium = 0, benignHigh = 0, benignMedium = 0;
        var added = new List<double>();
        using var reviews = new ReviewCounter([id]);

        foreach (var phrase in heldOut)
        {
            var started = Stopwatch.GetTimestamp();
            var result = await pipeline.RunAsync(Context(phrase.Text), ct).ConfigureAwait(false);
            var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            var severity = result.MaxSeverity;

            if (phrase.IsPositive)
            {
                if (severity >= Severity.High) positiveHigh++;
                if (severity >= Severity.Medium) positiveMedium++;
            }
            else
            {
                if (severity >= Severity.High) benignHigh++;
                if (severity >= Severity.Medium) benignMedium++;
                if (configuration == JudgedIndex && severity >= Severity.High)
                {
                    JudgedHighs.Add(string.Create(CultureInfo.InvariantCulture,
                        $"{id}: a legitimate request reached High with the judge: \"{phrase.Text}\""));
                }
            }

            if (configuration == CappedIndex) baseline[phrase.Text] = elapsed;
            else if (configuration == JudgedIndex) added.Add(elapsed - baseline.GetValueOrDefault(phrase.Text));
        }

        var positives = heldOut.Count(p => p.IsPositive);
        var benign = heldOut.Length - positives;
        var judged = configuration == JudgedIndex;
        var latency = judged
            ? $"{Percentile(added, 0.5):0.0} | {Percentile(added, 0.95):0.0}"
            : "n/a | n/a";
        // One detector proposes at most one candidate per scan, so its own budget is never exceeded: the full-pipeline
        // pass measures the budget across detectors.
        var perScan = judged ? PerScan(reviews.Candidates, heldOut.Length) : "n/a";
        if (judged) NoteJudgeOutcomes(id, reviews);
        return string.Create(CultureInfo.InvariantCulture,
            $"| {ConfigurationNames[configuration]} | {positiveHigh} / {positives} | {positiveMedium} / {positives} | {benignHigh} / {benign} | {benignMedium} / {benign} | {latency} | {perScan} |");
    }

    /// <summary>Lines shown beneath the detector's table: the review outcomes and any failure warning.</summary>
    private List<string> _notes = [];

    /// <summary>Reviews that failed or timed out across every detector; above 0 the judge columns are not valid.</summary>
    public long JudgeFailures { get; private set; }

    private void NoteJudgeOutcomes(string id, ReviewCounter reviews)
    {
        _notes.Add(string.Create(CultureInfo.InvariantCulture,
            $"Configuration 3 review outcomes for {id}: {reviews.Outcomes()}."));
        var failures = reviews.Failures;
        if (failures == 0) return;
        JudgeFailures += failures;
        _notes.Add(string.Create(CultureInfo.InvariantCulture,
            $"**WARNING: {failures} reviews failed or timed out for {id}; the judge columns are not valid.**"));
    }

    private const int CappedIndex = 1;
    private const int JudgedIndex = 2;

    private static string PerScan(long count, int scans) =>
        ((double)count / Math.Max(scans, 1)).ToString("0.00", CultureInfo.InvariantCulture);

    /// <summary>Counts the <c>sentinel.reviews</c> measurements for a set of detectors, by outcome.</summary>
    private sealed class ReviewCounter : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly Dictionary<string, long> _outcomes = new(StringComparer.Ordinal);

        public ReviewCounter(IReadOnlyCollection<string> detectorIds)
        {
            var ids = new HashSet<string>(detectorIds, StringComparer.Ordinal);
            _listener.InstrumentPublished = (instrument, l) =>
            {
                if (string.Equals(instrument.Meter.Name, "ai.sentinel", StringComparison.Ordinal)
                    && string.Equals(instrument.Name, "sentinel.reviews", StringComparison.Ordinal))
                {
                    l.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) => Record(ids, value, tags));
            _listener.Start();
        }

        private void Record(HashSet<string> ids, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            string? outcome = null;
            var forDetector = false;
            foreach (var tag in tags)
            {
                if (string.Equals(tag.Key, "outcome", StringComparison.Ordinal)) outcome = tag.Value as string;
                else if (string.Equals(tag.Key, "detector", StringComparison.Ordinal))
                {
                    forDetector = tag.Value is string id && ids.Contains(id);
                }
            }

            if (outcome is null || !forDetector) return;
            lock (_outcomes) _outcomes[outcome] = _outcomes.GetValueOrDefault(outcome) + value;
        }

        private long Count(string outcome)
        {
            lock (_outcomes) return _outcomes.GetValueOrDefault(outcome);
        }

        /// <summary>Every candidate: reviewed, failed, timed out or over budget.</summary>
        public long Candidates => ReviewOutcomes.All.Sum(Count);

        public long OverBudget => Count(ReviewOutcomes.OverBudget);

        public long Failures => Count(ReviewOutcomes.Failed) + Count(ReviewOutcomes.TimedOut);

        public string Outcomes() => string.Join(", ", ReviewOutcomes.All.Select(n =>
            string.Create(CultureInfo.InvariantCulture, $"{n} {Count(n)}")));

        public void Dispose() => _listener.Dispose();
    }

    /// <summary>Answers every review with no verdict and counts the calls, so the full-pipeline pass measures
    /// candidacy and the budget without a judge or a key.</summary>
    private sealed class CountingReviewer : IDetectionReviewer
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return ValueTask.FromResult(ReviewVerdict.None);
        }
    }

    /// <summary>Runs every detector in <paramref name="detectors"/> together, capped and with the default
    /// <c>MaxReviewsPerScan</c> of 4, over <paramref name="texts"/>, and reports how many review candidates a scan
    /// produces, how many are sent and the share over budget.</summary>
    /// <param name="scope">The embedding scope the detectors share.</param>
    /// <param name="detectors">The evaluated detectors, all enabled at once.</param>
    /// <param name="texts">Benign texts, each as a user message or, for a tool output, as a tool message.</param>
    /// <param name="title">The section title, such as <c>Full-pipeline review budget: fit</c>.</param>
    /// <param name="ct">Cancels the pass.</param>
    /// <returns>The <paramref name="title"/> Markdown section.</returns>
    /// <remarks>The reviewer answers no verdict, so no judge is needed and no result changes: this measures candidacy
    /// and the budget only. A benign text that becomes a candidate costs a review in production.</remarks>
    public static async Task<string> FullPipelineAsync(
        EmbeddingScope scope, IReadOnlyList<SemanticDetectorBase> detectors, IReadOnlyList<(string Text, bool Tool)> texts,
        string title, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(detectors);
        ArgumentNullException.ThrowIfNull(texts);
        ArgumentNullException.ThrowIfNull(title);
        var configurations = new Dictionary<Type, DetectorConfiguration>();
        foreach (var detector in detectors) configurations[detector.GetType()] = new DetectorConfiguration { Enabled = true };
        var reviewer = new CountingReviewer();
        var pipeline = new DetectionPipeline(detectors, configurations, reviewer, embeddingScope: scope);

        using var reviews = new ReviewCounter([.. detectors.Select(d => d.Id.Value)]);
        var maxCandidates = 0L;
        var scansOverBudget = 0;
        var scansWithCandidates = 0;
        foreach (var (text, tool) in texts)
        {
            var before = reviews.Candidates;
            await pipeline.RunAsync(Context(text, tool), ct).ConfigureAwait(false);
            var candidates = reviews.Candidates - before;
            maxCandidates = Math.Max(maxCandidates, candidates);
            if (candidates > 0) scansWithCandidates++;
            if (candidates > ReviewLimits.Default.MaxPerScan) scansOverBudget++;
        }

        var share = reviews.Candidates == 0
            ? "0%"
            : ((double)reviews.OverBudget / reviews.Candidates).ToString("P0", CultureInfo.InvariantCulture);
        var section = new StringBuilder();
        section.AppendLine(CultureInfo.InvariantCulture, $"### {title}");
        section.AppendLine();
        section.AppendLine(CultureInfo.InvariantCulture,
            $"All {detectors.Count} detectors above enabled together, capped, with the default budget of {ReviewLimits.Default.MaxPerScan} reviews per scan, over {texts.Count} benign texts. The reviewer answers no verdict, so no key is needed; this measures candidacy and the budget, not detection.");
        section.AppendLine();
        section.AppendLine("| Scans | Scans with a candidate | Candidates per scan | Reviews per scan | Most candidates in one scan | Scans over budget | Share of candidates over budget |");
        section.AppendLine("|---|---|---|---|---|---|---|");
        section.AppendLine(CultureInfo.InvariantCulture,
            $"| {texts.Count} | {scansWithCandidates} | {PerScan(reviews.Candidates, texts.Count)} | {PerScan(reviewer.Calls, texts.Count)} | {maxCandidates} | {scansOverBudget} | {share} |");
        section.AppendLine();
        section.AppendLine(CultureInfo.InvariantCulture, $"Review outcomes: {reviews.Outcomes()}.");
        section.AppendLine();
        return section.ToString();
    }

    private DetectionPipeline Pipeline(SemanticDetectorBase detector, bool capped, bool withReviewer) => new(
        [detector],
        new Dictionary<Type, DetectorConfiguration>
        {
            [detector.GetType()] = new() { Enabled = true, CapSemanticSeverity = capped },
        },
        withReviewer ? reviewer : null,
        embeddingScope: scope);

    /// <summary>A single message, so the detector scores exactly the phrase. Security phrases are tool messages, which
    /// keeps the rule layer silent; compliance phrases are user messages.</summary>
    private SentinelContext Context(string text) => Context(text, toolMessages);

    private static SentinelContext Context(string text, bool tool) => tool
        ? new SentinelContext(new AgentId("tool"), new AgentId("assistant"), SessionId.New(), [new ChatMessage(ChatRole.Tool, text)], [])
        : new SentinelContext(new AgentId("user"), new AgentId("assistant"), SessionId.New(), [new ChatMessage(ChatRole.User, text)], []);
}
