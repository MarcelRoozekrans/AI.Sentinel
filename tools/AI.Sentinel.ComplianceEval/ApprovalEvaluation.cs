using System.Globalization;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Approvals.Semantic;
using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.ComplianceEval;

/// <summary>Scores labelled tool-argument texts against the built-in semantic approval examples and derives the
/// default threshold: the lowest value, at 0.01 steps, strictly above every benign score of the deciding split.</summary>
/// <remarks>Each text is scored the way <c>SemanticApprovalMatcher</c> scores a call: the maximum cosine similarity
/// over <see cref="SemanticApprovalExamples.Default"/>, with <see cref="SemanticDetectorBase.MaxSimilarityIndex"/>.
/// Without tuning, the held-out split decides the threshold and fit texts are reported alongside; with tuning, only
/// fit texts are scored and decide it, so the output is safe to change the examples from.</remarks>
internal sealed class ApprovalEvaluation(IEmbeddingGenerator<string, Embedding<float>> generator, CancellationToken ct)
{
    private sealed record LabelledText(bool HeldOut, bool Destructive, string Value)
    {
        public string Split => HeldOut ? "heldOut" : "fit";

        public string Class => Destructive ? "destructive" : "benign";
    }

    private sealed record Score(LabelledText Text, float Similarity, string Example);

    /// <summary>The lowest threshold at 0.01 steps that is strictly above <paramref name="benignMax"/>.</summary>
    internal static decimal ThresholdAbove(float benignMax) =>
        (Math.Floor((decimal)benignMax * 100m) / 100m) + 0.01m;

    /// <summary>Checks <see cref="ThresholdAbove"/> on three cases, since the tool has no test project.</summary>
    /// <exception cref="InvalidOperationException">A case gave the wrong value.</exception>
    internal static void SelfCheck()
    {
        if (ThresholdAbove(0.8249f) != 0.83m || ThresholdAbove(0.85f) != 0.86m || ThresholdAbove(0.8001f) != 0.81m)
        {
            throw new InvalidOperationException("ApprovalEvaluation.ThresholdAbove self-check failed.");
        }
    }

    /// <summary>Evaluates the phrase file at <paramref name="path"/>.</summary>
    /// <param name="path">An <c>approval-phrases.json</c> file with <c>fit</c> and <c>heldOut</c> sections.</param>
    /// <param name="tuning">Score fit texts only, and derive the threshold from them.</param>
    /// <returns>The Markdown section.</returns>
    /// <exception cref="InvalidDataException">A text appears verbatim in the built-in examples.</exception>
    public async Task<string> EvaluateAsync(string path, bool tuning)
    {
        var texts = Load(path).Where(t => !tuning || !t.HeldOut).ToArray();
        var scores = await ScoreAsync(texts).ConfigureAwait(false);

        var deciding = scores.Where(s => s.Text.HeldOut != tuning).ToArray();
        var benignMax = deciding.Where(s => !s.Text.Destructive).Max(s => s.Similarity);
        var threshold = ThresholdAbove(benignMax);
        var thresholdF = (float)threshold;
        var destructive = deciding.Where(s => s.Text.Destructive).ToArray();
        var recalled = destructive.Count(s => s.Similarity >= thresholdF);
        var decidingName = tuning ? "fit" : "heldOut";

        var section = new StringBuilder();
        section.AppendLine("## Semantic approval threshold");
        section.AppendLine();
        section.AppendLine(CultureInfo.InvariantCulture,
            $"{SemanticApprovalExamples.Default.Length} built-in examples. Each text scores the maximum cosine similarity over them, as the matcher does. `DefaultThreshold` at run time: {SemanticApprovalExamples.DefaultThreshold:0.00}.");
        section.AppendLine();
        if (tuning)
        {
            section.AppendLine("Tuning mode: held-out texts are not scored; the threshold below comes from fit benign texts.");
            section.AppendLine();
        }

        section.Append(Distribution(scores, threshold));
        section.AppendLine();
        section.AppendLine(CultureInfo.InvariantCulture, $"- Highest {decidingName} benign score: {benignMax:0.0000}.");
        section.AppendLine(CultureInfo.InvariantCulture,
            $"- Chosen threshold, the lowest at 0.01 steps above it: **{threshold:0.00}**.");
        section.AppendLine(CultureInfo.InvariantCulture,
            $"- {decidingName} destructive recall at {threshold:0.00}: **{recalled} / {destructive.Length}, {(double)recalled / destructive.Length:P0}**.");
        section.AppendLine();
        section.Append(PerText(scores, thresholdF));
        return section.ToString();
    }

    private async Task<Score[]> ScoreAsync(LabelledText[] texts)
    {
        var examples = SemanticApprovalExamples.Default;
        var exampleSet = new HashSet<string>(examples, StringComparer.Ordinal);
        var copies = Array.FindAll(texts, t => exampleSet.Contains(t.Value));
        if (copies.Length > 0)
        {
            throw new InvalidDataException(
                $"Eval texts copy built-in examples: {string.Join("; ", Array.ConvertAll(copies, c => c.Value))}");
        }

        var exampleEmbeddings = await generator.GenerateAsync(examples, cancellationToken: ct).ConfigureAwait(false);
        var exampleVectors = new ReadOnlyMemory<float>[exampleEmbeddings.Count];
        for (var i = 0; i < exampleVectors.Length; i++) exampleVectors[i] = exampleEmbeddings[i].Vector;

        var values = Array.ConvertAll(texts, t => t.Value);
        var textEmbeddings = await generator.GenerateAsync(values, cancellationToken: ct).ConfigureAwait(false);
        var scores = new Score[texts.Length];
        for (var i = 0; i < texts.Length; i++)
        {
            var index = SemanticDetectorBase.MaxSimilarityIndex(textEmbeddings[i].Vector.Span, exampleVectors, out var similarity);
            scores[i] = new Score(texts[i], similarity, index < 0 ? "-" : examples[index]);
        }

        return scores;
    }

    private static string Distribution(Score[] scores, decimal threshold)
    {
        var thresholdF = (float)threshold;
        var groups = scores
            .GroupBy(s => (s.Text.HeldOut, s.Text.Destructive))
            .OrderBy(g => g.Key.HeldOut).ThenBy(g => g.Key.Destructive ? 0 : 1)
            .Select(g => (Key: g.First().Text, Values: g.Select(s => (double)s.Similarity).ToArray()))
            .ToArray();

        var table = new StringBuilder();
        table.AppendLine(CultureInfo.InvariantCulture, $"Score distribution, with the count at or above the chosen threshold {threshold:0.00}:");
        table.AppendLine();
        table.AppendLine("| Split | Class | Count | Min | p50 | p95 | Max | At or above threshold |");
        table.AppendLine("|---|---|---|---|---|---|---|---|");
        foreach (var (key, values) in groups)
        {
            double min = double.MaxValue, max = double.MinValue;
            var flagged = 0;
            foreach (var v in values)
            {
                min = Math.Min(min, v);
                max = Math.Max(max, v);
                if ((float)v >= thresholdF) flagged++;
            }

            table.AppendLine(CultureInfo.InvariantCulture,
                $"| {key.Split} | {key.Class} | {values.Length} | {min:0.000} | {ReviewEvaluation.Percentile(values, 0.5):0.000} | {ReviewEvaluation.Percentile(values, 0.95):0.000} | {max:0.000} | {flagged} / {values.Length} |");
        }

        return table.ToString();
    }

    private static string PerText(Score[] scores, float threshold)
    {
        var table = new StringBuilder();
        table.AppendLine("### Per text");
        table.AppendLine();
        table.AppendLine("| Split | Class | Score | Flagged | Text | Nearest example |");
        table.AppendLine("|---|---|---|---|---|---|");
        var ordered = scores
            .OrderBy(s => s.Text.HeldOut).ThenBy(s => s.Text.Destructive ? 0 : 1).ThenByDescending(s => s.Similarity)
            .ToArray();
        foreach (var s in ordered)
        {
            table.AppendLine(CultureInfo.InvariantCulture,
                $"| {s.Text.Split} | {s.Text.Class} | {s.Similarity:0.000} | {(s.Similarity >= threshold ? "yes" : "no")} | `{Cell(s.Text.Value)}` | `{Cell(s.Example)}` |");
        }

        table.AppendLine();
        return table.ToString();
    }

    private static string Cell(string text) =>
        text.Replace("|", "\\|", StringComparison.Ordinal).Replace("`", "'", StringComparison.Ordinal);

    private static LabelledText[] Load(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var texts = new List<LabelledText>();
        AddSection(texts, document.RootElement.GetProperty("fit"), heldOut: false);
        AddSection(texts, document.RootElement.GetProperty("heldOut"), heldOut: true);
        return [.. texts];
    }

    private static void AddSection(List<LabelledText> texts, JsonElement section, bool heldOut)
    {
        foreach (var e in section.GetProperty("destructive").EnumerateArray()) texts.Add(new LabelledText(heldOut, true, e.GetString()!));
        foreach (var e in section.GetProperty("benign").EnumerateArray()) texts.Add(new LabelledText(heldOut, false, e.GetString()!));
    }
}
