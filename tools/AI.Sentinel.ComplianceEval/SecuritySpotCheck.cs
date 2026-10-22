using System.Globalization;
using System.Text;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.ComplianceEval;

/// <summary>Spot-checks a security detector, such as SEC-01, SEC-05 or SEC-09, on a labelled set of paraphrased
/// attacks and benign texts. Each phrase is scored against the detector's High, Medium and Low examples with
/// <see cref="SemanticDetectorBase.MaxSimilarity"/>; the first bucket that reaches its threshold, in that order, gives
/// the verdict, which the detector's <see cref="IDetector.AnalyzeAsync"/> must confirm. The check reports the numbers
/// and does not tune: these thresholds are not derived from this set.</summary>
/// <param name="failures">Where problems that fail the run go: a detector that disagrees with the tool, or a benign
/// text in the High bucket.</param>
internal sealed class SecuritySpotCheck(
    IEmbeddingGenerator<string, Embedding<float>> generator, List<string> failures, CancellationToken ct)
{
    /// <summary>Evaluates <paramref name="detector"/>: the positives written for it, and every benign text.</summary>
    /// <returns>The summary row, and the per-phrase table.</returns>
    public async Task<(string SummaryRow, string Table)> EvaluateAsync(SemanticDetectorBase detector, Phrase[] phrases)
    {
        ArgumentNullException.ThrowIfNull(detector);
        var id = detector.Id.Value;
        var high = await VectorsAsync(detector.EvaluationHighExamples).ConfigureAwait(false);
        var medium = await VectorsAsync(detector.EvaluationMediumExamples).ConfigureAwait(false);
        var low = await VectorsAsync(detector.EvaluationLowExamples).ConfigureAwait(false);
        var highThreshold = detector.EvaluationHighThreshold;
        var mediumThreshold = detector.EvaluationMediumThreshold;
        var lowThreshold = detector.EvaluationLowThreshold;
        var thresholds = string.Create(CultureInfo.InvariantCulture,
            $"{highThreshold:0.00} / {mediumThreshold:0.00} / {(low.Length == 0 ? "-" : lowThreshold.ToString("0.00", CultureInfo.InvariantCulture))}");

        var table = new StringBuilder();
        table.AppendLine(CultureInfo.InvariantCulture,
            $"### {id}: High {highThreshold:0.00} {detector.EvaluationHighSeverity}, Medium {mediumThreshold:0.00} {detector.EvaluationMediumSeverity}, Low {(low.Length == 0 ? "no examples" : string.Create(CultureInfo.InvariantCulture, $"{lowThreshold:0.00} {detector.EvaluationLowSeverity}"))}");
        table.AppendLine();
        table.AppendLine("| Phrase | Written for | Expected | High set | Medium set | Low set | Result |");
        table.AppendLine("|---|---|---|---|---|---|---|");

        var tally = new Tally();
        var rows = phrases
            .Where(p => !p.IsPositive || string.Equals(p.Detector, id, StringComparison.Ordinal))
            .OrderBy(p => p.IsPositive ? 0 : 1);

        foreach (var row in rows)
        {
            var vector = (await generator.GenerateAsync([row.Text], cancellationToken: ct).ConfigureAwait(false))[0].Vector;
            var highSimilarity = SemanticDetectorBase.MaxSimilarity(vector.Span, high);
            var mediumSimilarity = SemanticDetectorBase.MaxSimilarity(vector.Span, medium);
            var lowSimilarity = SemanticDetectorBase.MaxSimilarity(vector.Span, low);
            var bucket =
                high.Length > 0 && highSimilarity >= highThreshold ? Bucket.High
                : medium.Length > 0 && mediumSimilarity >= mediumThreshold ? Bucket.Medium
                : low.Length > 0 && lowSimilarity >= lowThreshold ? Bucket.Low
                : Bucket.None;
            var computed = SeverityOf(detector, bucket);

            var actual = (await detector.AnalyzeAsync(Context(row.Text), ct).ConfigureAwait(false)).Severity;
            if (actual != computed)
            {
                failures.Add(string.Create(CultureInfo.InvariantCulture,
                    $"{id}: detector returned {actual}, tool computed {computed} for \"{row.Text}\""));
            }

            if (!row.IsPositive && bucket == Bucket.High)
            {
                failures.Add(string.Create(CultureInfo.InvariantCulture,
                    $"{id}: benign text reached the High set at {highSimilarity:0.000}: \"{row.Text}\""));
            }

            tally.Record(row.IsPositive, bucket, highSimilarity, mediumSimilarity);
            var lowCell = low.Length == 0 ? "-" : lowSimilarity.ToString("0.000", CultureInfo.InvariantCulture);
            table.AppendLine(CultureInfo.InvariantCulture,
                $"| {row.Display} | {row.Detector} | {row.Expected} | {highSimilarity:0.000} | {mediumSimilarity:0.000} | {lowCell} | {Label(bucket, actual, row.IsPositive)} |");
        }

        table.AppendLine();
        var summary = string.Create(CultureInfo.InvariantCulture,
            $"| {id} | {thresholds} | {Evaluator.Format(tally.LowestPositive)} | {tally.HighestBenignHigh:0.000} | {tally.HighestBenignMedium:0.000} | {tally.Positives[0]} / {tally.Positives[1]} / {tally.Positives[2]} / {tally.Positives[3]} | {tally.Benign[0]} / {tally.Benign[1]} / {tally.Benign[2]} |");
        return (summary, table.ToString());
    }

    /// <summary>The bucket a phrase reaches, in the order the detector checks them. The values index the tallies.</summary>
    private enum Bucket
    {
        High = 0,
        Medium = 1,
        Low = 2,
        None = 3,
    }

    private static Severity SeverityOf(SemanticDetectorBase detector, Bucket bucket) => bucket switch
    {
        Bucket.High => detector.EvaluationHighSeverity,
        Bucket.Medium => detector.EvaluationMediumSeverity,
        Bucket.Low => detector.EvaluationLowSeverity,
        _ => Severity.None,
    };

    /// <summary>The bucket and the severity the detector returned, flagged as missed or false positive.</summary>
    private static string Label(Bucket bucket, Severity actual, bool positive) => (bucket, positive) switch
    {
        (Bucket.High, true) => $"High ({actual})",
        (Bucket.Medium, true) => $"Medium ({actual}, High missed)",
        (Bucket.Low, true) => $"Low ({actual}, High missed)",
        (_, true) => "Clean (missed)",
        (Bucket.High, false) => $"**High ({actual}, false positive)**",
        (Bucket.Medium, false) => $"Medium ({actual})",
        (Bucket.Low, false) => $"Low ({actual})",
        _ => "Clean",
    };

    private async Task<ReadOnlyMemory<float>[]> VectorsAsync(string[] examples)
    {
        if (examples.Length == 0) return [];
        var embeddings = await generator.GenerateAsync(examples, cancellationToken: ct).ConfigureAwait(false);
        return [.. embeddings.Select(e => e.Vector)];
    }

    /// <summary>A single tool message: the rule layer judges only a newest user message, so it stays silent and the
    /// verdict is the semantic one.</summary>
    private static SentinelContext Context(string text) => new(
        new AgentId("tool"), new AgentId("assistant"), SessionId.New(),
        [new ChatMessage(ChatRole.Tool, text)], []);

    /// <summary>Per-detector counts by bucket, and the extremes for the summary row.</summary>
    private sealed class Tally
    {
        /// <summary>Positives at High, Medium, Low and missed, indexed by <see cref="Bucket"/>.</summary>
        public int[] Positives { get; } = new int[4];

        /// <summary>Benign texts at High, Medium and Low, indexed by <see cref="Bucket"/>; the last slot counts Clean.</summary>
        public int[] Benign { get; } = new int[4];

        public float LowestPositive { get; private set; } = float.MaxValue;
        public float HighestBenignHigh { get; private set; }
        public float HighestBenignMedium { get; private set; }

        public void Record(bool positive, Bucket bucket, float highSimilarity, float mediumSimilarity)
        {
            if (positive)
            {
                Positives[(int)bucket]++;
                LowestPositive = Math.Min(LowestPositive, highSimilarity);
                return;
            }

            Benign[(int)bucket]++;
            HighestBenignHigh = Math.Max(HighestBenignHigh, highSimilarity);
            HighestBenignMedium = Math.Max(HighestBenignMedium, mediumSimilarity);
        }
    }
}
