// Scores the Art. 5 compliance detectors, CMP-01 to CMP-04, against a real embedding model.
//
//   dotnet run --project tools/AI.Sentinel.ComplianceEval -- [--model all-MiniLM-L6-v2|bge-base-en-v1.5]
//       [--model-dir <dir>] [--phrases <compliance-phrases.json>] [--everyday <everyday-prompts.json>]
//       [--out <results.md>]
//
// Positives are scored against the detector they were written for; near-misses and everyday prompts against all
// four, because a legitimate request must not trip any of them. Exit code 1 means a legitimate request reached
// High with the detectors' current thresholds, or a detector disagreed with the tool's own scoring.
using System.Globalization;
using System.Text;
using AI.Sentinel;
using AI.Sentinel.ComplianceEval;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;

var ct = CancellationToken.None;
var modelName = Option(args, "--model") ?? EmbeddingModel.Known[0].Name;
var model = Array.Find(EmbeddingModel.Known, m => string.Equals(m.Name, modelName, StringComparison.OrdinalIgnoreCase));
if (model is null)
{
    await Console.Error.WriteLineAsync(
        $"Unknown model '{modelName}'. Known: {string.Join(", ", EmbeddingModel.Known.Select(m => m.Name))}").ConfigureAwait(false);
    return 2;
}

var phrasesPath = Option(args, "--phrases") ?? Path.Combine(
    RepositoryRoot(), "tests", "AI.Sentinel.Tests", "Detectors", "Compliance", "compliance-phrases.json");
var everydayPath = Option(args, "--everyday") ?? Path.Combine(
    RepositoryRoot(), "tools", "AI.Sentinel.ComplianceEval", "everyday-prompts.json");
var outPath = Option(args, "--out");

var directory = await model.EnsureAsync(Option(args, "--model-dir"), ct).ConfigureAwait(false);
using var generator = new OnnxSentenceEmbeddingGenerator(model, directory);
var evaluator = new Evaluator(generator, ct);

var report = new StringBuilder();
report.AppendLine(CultureInfo.InvariantCulture, $"## Results: {model.Name}");
report.AppendLine();
report.AppendLine(CultureInfo.InvariantCulture,
    $"Model `{model.Repository}`, ONNX export, {model.Pooling} pooling, L2-normalised. Run {DateTime.UtcNow:yyyy-MM-dd}.");
report.AppendLine();

// Pipeline check: a paraphrase must score well above an unrelated sentence, or the tokenizer or pooling is wrong.
report.AppendLine("Pipeline check, cosine similarity:");
report.AppendLine();
(string A, string B)[] pairs =
[
    ("A man is eating food.", "A man is eating a piece of bread."),
    ("A man is eating food.", "A man is riding a horse."),
    ("How do I reset my password?", "I forgot my login credentials, how can I change them?"),
    ("How do I reset my password?", "The weather in Amsterdam is mild today."),
];
foreach (var (a, b) in pairs)
{
    var similarity = await evaluator.SimilarityAsync(a, b).ConfigureAwait(false);
    report.AppendLine(CultureInfo.InvariantCulture, $"- {similarity:0.000}: \"{a}\" / \"{b}\"");
}

report.AppendLine();

var options = new SentinelOptions { EmbeddingGenerator = generator };
SemanticDetectorBase[] detectors =
[
    new SocialScoringDetector(options),
    new WorkplaceEmotionRecognitionDetector(options),
    new SensitiveBiometricCategorisationDetector(options),
    new ProfilingCrimePredictionDetector(options),
];

Phrase[] phrases = [.. Phrase.Load(phrasesPath), .. Phrase.Load(everydayPath)];
var summary = new StringBuilder();
summary.AppendLine("| Detector | High / Medium threshold | Lowest positive, High set | Highest legitimate, High set | Highest legitimate, Medium set | Positives at High / Medium / missed | Legitimate at High / Medium | Rule's thresholds for this model: positives at High / Medium / missed |");
summary.AppendLine("|---|---|---|---|---|---|---|---|");
var tables = new StringBuilder();
foreach (var detector in detectors)
{
    var (row, table) = await evaluator.EvaluateAsync(detector, phrases).ConfigureAwait(false);
    summary.AppendLine(row);
    tables.Append(table);
}

report.AppendLine("### Summary");
report.AppendLine();
report.Append(summary);
report.AppendLine();
report.Append(tables);

if (evaluator.Failures.Count > 0)
{
    report.AppendLine("### Failures");
    report.AppendLine();
    foreach (var failure in evaluator.Failures) report.AppendLine(CultureInfo.InvariantCulture, $"- {failure}");
    report.AppendLine();
}

if (outPath is null) Console.Write(report.ToString());
else await File.WriteAllTextAsync(outPath, report.ToString(), ct).ConfigureAwait(false);

foreach (var failure in evaluator.Failures) await Console.Error.WriteLineAsync(failure).ConfigureAwait(false);
return evaluator.Failures.Count == 0 ? 0 : 1;

static string? Option(string[] args, string name)
{
    var index = Array.FindIndex(args, a => string.Equals(a, name, StringComparison.Ordinal));
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static string RepositoryRoot()
{
    for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
    {
        if (File.Exists(Path.Combine(dir.FullName, "AI.Sentinel.slnx"))) return dir.FullName;
    }

    throw new InvalidOperationException("Could not find the repository root; pass --phrases.");
}
