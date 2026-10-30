using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.ComplianceEval;

/// <summary>Scores the held-out phrases through an internal <see cref="DetectionPipeline"/> over one detector, in three
/// configurations: embeddings alone and uncapped, embeddings capped at Medium, and embeddings plus a reviewer.</summary>
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
        section.AppendLine("| Config | Positives >= High | Positives >= Medium | Benign >= High | Benign >= Medium | p50 added ms | p95 added ms | Reviews per scan | Share over budget |");
        section.AppendLine("|---|---|---|---|---|---|---|---|---|");

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
                    $"| {ConfigurationNames[c]} | skipped | skipped | skipped | skipped | skipped | skipped | skipped | skipped |");
                continue;
            }

            section.AppendLine(await RunConfigurationAsync(c, pipeline, detector, heldOut, baseline).ConfigureAwait(false));
        }

        section.AppendLine();
        return section.ToString();
    }

    private async Task<string> RunConfigurationAsync(
        int configuration, DetectionPipeline pipeline, SemanticDetectorBase detector, Phrase[] heldOut, Dictionary<string, double> baseline)
    {
        var id = detector.Id.Value;
        int positiveHigh = 0, positiveMedium = 0, benignHigh = 0, benignMedium = 0;
        var added = new List<double>();
        using var reviews = new ReviewCounter(id);

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
            ? $"{Percentile(added, 0.5):0} | {Percentile(added, 0.95):0}"
            : "n/a | n/a";
        var perScan = judged ? reviews.PerScan(heldOut.Length) : "n/a";
        var share = judged ? reviews.OverBudgetShare() : "n/a";
        return string.Create(CultureInfo.InvariantCulture,
            $"| {ConfigurationNames[configuration]} | {positiveHigh} / {positives} | {positiveMedium} / {positives} | {benignHigh} / {benign} | {benignMedium} / {benign} | {latency} | {perScan} | {share} |");
    }

    private const int CappedIndex = 1;
    private const int JudgedIndex = 2;

    /// <summary>Counts the <c>sentinel.reviews</c> measurements for one detector, by outcome.</summary>
    private sealed class ReviewCounter : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly Dictionary<string, long> _outcomes = new(StringComparer.Ordinal);

        public ReviewCounter(string detectorId)
        {
            _listener.InstrumentPublished = (instrument, l) =>
            {
                if (string.Equals(instrument.Meter.Name, "ai.sentinel", StringComparison.Ordinal)
                    && string.Equals(instrument.Name, "sentinel.reviews", StringComparison.Ordinal))
                {
                    l.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) => Record(detectorId, value, tags));
            _listener.Start();
        }

        private void Record(string detectorId, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            string? outcome = null;
            var forDetector = false;
            foreach (var tag in tags)
            {
                if (string.Equals(tag.Key, "outcome", StringComparison.Ordinal)) outcome = tag.Value as string;
                else if (string.Equals(tag.Key, "detector", StringComparison.Ordinal))
                {
                    forDetector = string.Equals(tag.Value as string, detectorId, StringComparison.Ordinal);
                }
            }

            if (outcome is null || !forDetector) return;
            lock (_outcomes) _outcomes[outcome] = _outcomes.GetValueOrDefault(outcome) + value;
        }

        private long Reviewed => _outcomes.Where(o => !string.Equals(o.Key, "over_budget", StringComparison.Ordinal)).Sum(o => o.Value);

        public string PerScan(int scans) =>
            ((double)Reviewed / Math.Max(scans, 1)).ToString("0.00", CultureInfo.InvariantCulture);

        public string OverBudgetShare()
        {
            var over = _outcomes.GetValueOrDefault("over_budget");
            var candidates = Reviewed + over;
            return candidates == 0 ? "0%" : ((double)over / candidates).ToString("P0", CultureInfo.InvariantCulture);
        }

        public void Dispose() => _listener.Dispose();
    }

    private DetectionPipeline Pipeline(SemanticDetectorBase detector, bool capped, bool withReviewer) => new(
        [detector],
        new Dictionary<Type, DetectorConfiguration>
        {
            [detector.GetType()] = new() { CapSemanticSeverity = capped },
        },
        withReviewer ? reviewer : null,
        embeddingScope: scope);

    /// <summary>A single message, so the detector scores exactly the phrase. Security phrases are tool messages, which
    /// keeps the rule layer silent; compliance phrases are user messages.</summary>
    private SentinelContext Context(string text) => toolMessages
        ? new SentinelContext(new AgentId("tool"), new AgentId("assistant"), SessionId.New(), [new ChatMessage(ChatRole.Tool, text)], [])
        : new SentinelContext(new AgentId("user"), new AgentId("assistant"), SessionId.New(), [new ChatMessage(ChatRole.User, text)], []);
}
