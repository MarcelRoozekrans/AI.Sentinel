using System.Globalization;
using System.Text;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.ComplianceEval;

/// <summary>Scores phrases against one detector's High and Medium examples with
/// <see cref="SemanticDetectorBase.MaxSimilarity"/>, the detector's own math, and confirms the detector's
/// <see cref="IDetector.AnalyzeAsync"/> reaches the same verdict, for the phrase on its own and as the last of
/// several new messages.</summary>
internal sealed class Evaluator(IEmbeddingGenerator<string, Embedding<float>> generator, CancellationToken ct)
{
    /// <summary>Problems that fail the run: a near-miss or everyday prompt at High, or a detector that disagrees with the
    /// tool, on one message or on several.</summary>
    public List<string> Failures { get; } = [];

    /// <summary>Cosine similarity of two sentences, for the pipeline check.</summary>
    public async Task<float> SimilarityAsync(string a, string b)
    {
        var pair = await generator.GenerateAsync([a, b], cancellationToken: ct).ConfigureAwait(false);
        return SemanticDetectorBase.MaxSimilarity(pair[0].Vector.Span, [pair[1].Vector]);
    }

    /// <summary>Evaluates <paramref name="detector"/>: positives written for it, and every near-miss and everyday prompt.</summary>
    /// <param name="history">Benign prompts that precede each phrase in the multi-message pass. Each phrase is also
    /// scored as the last of these, all as new user messages, and the detector must return the most severe of the
    /// verdicts the tool computes for the phrase and for each history prompt on its own.</param>
    /// <returns>The summary row, and the per-phrase table.</returns>
    public async Task<(string SummaryRow, string Table)> EvaluateAsync(SemanticDetectorBase detector, Phrase[] phrases, IReadOnlyList<string> history)
    {
        ArgumentNullException.ThrowIfNull(detector);
        ArgumentNullException.ThrowIfNull(history);
        var id = detector.Id.Value;
        var high = await VectorsAsync(detector.EvaluationHighExamples).ConfigureAwait(false);
        var medium = await VectorsAsync(detector.EvaluationMediumExamples).ConfigureAwait(false);
        var highThreshold = detector.EvaluationHighThreshold;
        var mediumThreshold = detector.EvaluationMediumThreshold;

        var strongestHistory = await StrongestVerdictAsync(history, high, medium, highThreshold, mediumThreshold).ConfigureAwait(false);
        var multiAgrees = 0;
        var multiTotal = 0;

        var table = new StringBuilder();
        table.AppendLine(CultureInfo.InvariantCulture, $"### {id}: High {highThreshold:0.00}, Medium {mediumThreshold:0.00}");
        table.AppendLine();
        table.AppendLine("| Phrase | Written for | Expected | High set | Medium set | Result |");
        table.AppendLine("|---|---|---|---|---|---|");

        var tally = new Tally();
        var rows = phrases
            .Where(p => !p.IsPositive || string.Equals(p.Detector, id, StringComparison.Ordinal))
            .OrderBy(p => p.IsPositive ? 0 : 1);

        foreach (var row in rows)
        {
            var vector = (await generator.GenerateAsync([row.Text], cancellationToken: ct).ConfigureAwait(false))[0].Vector;
            var highSimilarity = SemanticDetectorBase.MaxSimilarity(vector.Span, high);
            var mediumSimilarity = SemanticDetectorBase.MaxSimilarity(vector.Span, medium);
            var computed = Verdict(highSimilarity >= highThreshold, mediumSimilarity >= mediumThreshold);

            var actual = (await detector.AnalyzeAsync(Context(row.Text), ct).ConfigureAwait(false)).Severity;
            if (actual != computed)
            {
                Failures.Add(string.Create(CultureInfo.InvariantCulture,
                    $"{id}: detector returned {actual}, tool computed {computed} for \"{row.Text}\""));
            }

            multiTotal++;
            var strongest = computed > strongestHistory ? computed : strongestHistory;
            if (await MultiMessageAgreesAsync(detector, history, row.Text, strongest).ConfigureAwait(false)) multiAgrees++;

            tally.Record(row.IsPositive, actual, highSimilarity, mediumSimilarity);
            if (!row.IsPositive && actual == Severity.High)
            {
                Failures.Add(string.Create(CultureInfo.InvariantCulture,
                    $"{id}: legitimate request reached High at {highSimilarity:0.000}: \"{row.Text}\""));
            }

            table.AppendLine(CultureInfo.InvariantCulture,
                $"| {row.Display} | {row.Detector} | {row.Expected} | {highSimilarity:0.000} | {mediumSimilarity:0.000} | {Label(actual, row.IsPositive)} |");
        }

        table.AppendLine();
        var summary = string.Create(CultureInfo.InvariantCulture,
            $"| {id} | {highThreshold:0.00} / {mediumThreshold:0.00} | {Format(tally.LowestPositive)} | {tally.HighestLegitimateHigh:0.000} | {tally.HighestLegitimateMedium:0.000} | {tally.PositiveHigh} / {tally.PositiveMedium} / {tally.PositiveMissed} | {tally.LegitimateHigh} / {tally.LegitimateMedium} | {tally.Suggestion()} | {multiAgrees} / {multiTotal} |");
        return (summary, table.ToString());
    }

    /// <summary>The most severe verdict the tool computes for any of <paramref name="texts"/> on its own.</summary>
    private async Task<Severity> StrongestVerdictAsync(
        IReadOnlyList<string> texts, ReadOnlyMemory<float>[] high, ReadOnlyMemory<float>[] medium, float highThreshold, float mediumThreshold)
    {
        var strongest = Severity.None;
        foreach (var vector in await VectorsAsync([.. texts]).ConfigureAwait(false))
        {
            var verdict = Verdict(
                SemanticDetectorBase.MaxSimilarity(vector.Span, high) >= highThreshold,
                SemanticDetectorBase.MaxSimilarity(vector.Span, medium) >= mediumThreshold);
            if (verdict > strongest) strongest = verdict;
        }

        return strongest;
    }

    /// <summary>Runs <paramref name="detector"/> on <paramref name="history"/> followed by <paramref name="text"/>, and
    /// records a failure when it does not return <paramref name="expected"/>, the strongest single-message verdict.</summary>
    private async Task<bool> MultiMessageAgreesAsync(SemanticDetectorBase detector, IReadOnlyList<string> history, string text, Severity expected)
    {
        var actual = (await detector.AnalyzeAsync(Context(history, text), ct).ConfigureAwait(false)).Severity;
        if (actual == expected) return true;

        Failures.Add(string.Create(CultureInfo.InvariantCulture,
            $"{detector.Id.Value}: multi-message context returned {actual}, strongest single message {expected} for \"{text}\""));
        return false;
    }

    /// <summary>A similarity to three decimals, or <c>n/a</c> when no value was recorded.</summary>
    internal static string Format(float value) =>
        value == float.MaxValue ? "n/a" : value.ToString("0.000", CultureInfo.InvariantCulture);

    private static Severity Verdict(bool high, bool medium) =>
        high ? Severity.High : medium ? Severity.Medium : Severity.None;

    private static string Label(Severity actual, bool positive) => (actual, positive) switch
    {
        (Severity.High, true) => "High",
        (Severity.Medium, true) => "Medium (High missed)",
        (_, true) => "Clean (missed)",
        (Severity.High, false) => "**High (false positive)**",
        (Severity.Medium, false) => "Medium (logged)",
        _ => "Clean",
    };

    private async Task<ReadOnlyMemory<float>[]> VectorsAsync(string[] examples)
    {
        if (examples.Length == 0) return [];
        var embeddings = await generator.GenerateAsync(examples, cancellationToken: ct).ConfigureAwait(false);
        return [.. embeddings.Select(e => e.Vector)];
    }

    /// <summary>A single user message, so <see cref="SentinelContext.TextContent"/> is exactly the phrase.</summary>
    private static SentinelContext Context(string text) => new(
        new AgentId("user"), new AgentId("assistant"), SessionId.New(),
        [new ChatMessage(ChatRole.User, text)], []);

    /// <summary><paramref name="history"/> followed by <paramref name="text"/>, all user messages, all new.</summary>
    private static SentinelContext Context(IReadOnlyList<string> history, string text)
    {
        var messages = new List<ChatMessage>(history.Count + 1);
        foreach (var prompt in history) messages.Add(new ChatMessage(ChatRole.User, prompt));
        messages.Add(new ChatMessage(ChatRole.User, text));
        return new SentinelContext(new AgentId("user"), new AgentId("assistant"), SessionId.New(), messages, [])
        {
            NewMessagesFrom = 0,
        };
    }

    /// <summary>Per-detector counts and extremes for the summary row, and the thresholds the tuning rule gives.</summary>
    /// <remarks>The rule: High is the highest legitimate similarity to the High set plus 0.05, Medium the highest
    /// legitimate similarity to the Medium set plus 0.02, both rounded up to 0.01, with Medium kept below High.
    /// High gets the wider margin because it raises an Alert; Medium is only logged.</remarks>
    private sealed class Tally
    {
        private readonly List<(float High, float Medium)> _positives = [];

        public float LowestPositive { get; private set; } = float.MaxValue;
        public float HighestLegitimateHigh { get; private set; }
        public float HighestLegitimateMedium { get; private set; }
        public int PositiveHigh { get; private set; }
        public int PositiveMedium { get; private set; }
        public int PositiveMissed { get; private set; }
        public int LegitimateHigh { get; private set; }
        public int LegitimateMedium { get; private set; }

        public void Record(bool positive, Severity actual, float highSimilarity, float mediumSimilarity)
        {
            if (positive)
            {
                _positives.Add((highSimilarity, mediumSimilarity));
                LowestPositive = Math.Min(LowestPositive, highSimilarity);
                if (actual == Severity.High) PositiveHigh++;
                else if (actual == Severity.Medium) PositiveMedium++;
                else PositiveMissed++;
                return;
            }

            HighestLegitimateHigh = Math.Max(HighestLegitimateHigh, highSimilarity);
            HighestLegitimateMedium = Math.Max(HighestLegitimateMedium, mediumSimilarity);
            if (actual == Severity.High) LegitimateHigh++;
            else if (actual == Severity.Medium) LegitimateMedium++;
        }

        /// <summary>The thresholds the rule gives for this model, and how the positives would fare under them.</summary>
        public string Suggestion()
        {
            var high = RoundUp(HighestLegitimateHigh + 0.05f);
            var medium = Math.Min(RoundUp(HighestLegitimateMedium + 0.02f), high - 0.01f);
            int atHigh = 0, atMedium = 0, missed = 0;
            foreach (var (h, m) in _positives)
            {
                if (h >= high) atHigh++;
                else if (m >= medium) atMedium++;
                else missed++;
            }

            return string.Create(CultureInfo.InvariantCulture, $"{high:0.00} / {medium:0.00}: {atHigh} / {atMedium} / {missed}");
        }

        private static float RoundUp(float value) => MathF.Ceiling(MathF.Round(value * 100f, 3)) / 100f;
    }
}
