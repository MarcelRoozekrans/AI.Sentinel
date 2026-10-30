// Scores the Art. 5 compliance detectors, CMP-01 to CMP-04, against a real embedding model, and spot-checks the
// security detectors SEC-01, SEC-05 and SEC-09.
//
//   dotnet run --project tools/AI.Sentinel.ComplianceEval -- [--model all-MiniLM-L6-v2|bge-base-en-v1.5]
//       [--model-dir <dir>] [--phrases <compliance-phrases.json>] [--everyday <everyday-prompts.json>]
//       [--security-phrases <security-phrases.json>] [--judge-model <id>] [--tuning] [--out <results.md>]
//
// Positives are scored against the detector they were written for; near-misses and everyday prompts against all
// four, because a legitimate request must not trip any of them. Each compliance phrase is scored a second time as
// the last of six new user messages, after the first five everyday prompts, and the detector must return the most
// severe single-message verdict. The security spot-check scores its positives against their own detector and its
// benign texts against all three, each as one tool message so the rule layer stays silent.
// Exit code 1 means a legitimate request reached High with the detectors' current thresholds, or a detector
// disagreed with the tool's own scoring, on one message or several, in either part.
// The held-out review section scores the held-out phrases in three configurations: embeddings uncapped, embeddings
// capped at Medium, and embeddings plus an LLM judge, which needs ANTHROPIC_API_KEY. It is reported and never fails the run.
// Embeddings are cached by configurations 1 and 2, so the judge's added ms is review latency only, not cold-scan latency.
// Configuration 3 reviews run under a 30 s measurement timeout, not a deployment's ReviewTimeout. The report counts the
// reviews over the hook CLIs' 3 s default and over the library's 5 s default, which a deployment with that timeout
// would abandon, and names each review over 3 s with its detector and the phrase's label.
// The full-pipeline pass then runs all seven detectors together with the default budget of 4 reviews per scan over
// the everyday prompts and the held-out benign texts, with a reviewer that answers no verdict, so it needs no key.
// It reports candidates and reviews per scan and the share of candidates over budget, once over the fit benign texts
// and once over the held-out ones.
// With --tuning only fit phrases are scored, the held-out sections are skipped, and the output is safe to tune
// thresholds from. Both summaries end in two candidacy columns, from fit phrases only: the lowest fit positive over
// any set, and the fit legitimate texts at or above it. The security spot-check also scores the everyday prompts as
// benign tool messages, and its fit columns add the rule's thresholds.
using System.Globalization;
using System.Text;
using AI.Sentinel;
using AI.Sentinel.ComplianceEval;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Review;
using Microsoft.Extensions.AI;

ReviewEvaluation.SelfCheck();
ThresholdRule.SelfCheck();
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
var securityPath = Option(args, "--security-phrases") ?? Path.Combine(
    RepositoryRoot(), "tools", "AI.Sentinel.ComplianceEval", "security-phrases.json");
var outPath = Option(args, "--out");
var tuning = args.Contains("--tuning", StringComparer.Ordinal);
var judgeModel = Option(args, "--judge-model") ?? "claude-sonnet-5-5";

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

var everyday = Phrase.Load(everydayPath);
var compliancePhrases = Phrase.Load(phrasesPath);
if (tuning)
{
    everyday = [.. everyday.Where(p => !p.IsHeldOut)];
    compliancePhrases = [.. compliancePhrases.Where(p => !p.IsHeldOut)];
}

string[] history = [.. everyday.Take(5).Select(p => p.Text)];
Phrase[] phrases = [.. compliancePhrases, .. everyday];
var summary = new StringBuilder();
summary.AppendLine("| Detector | High / Medium threshold | Lowest positive, High set | Highest legitimate, High set | Highest legitimate, Medium set | Positives at High / Medium / missed | Legitimate at High / Medium | Rule's thresholds for this model: positives at High / Medium / missed | Lowest fit positive, any set | Fit legitimate at or above it | Multi-message agrees |");
summary.AppendLine("|---|---|---|---|---|---|---|---|---|---|---|");
var tables = new StringBuilder();
foreach (var detector in detectors)
{
    var (row, table) = await evaluator.EvaluateAsync(detector, phrases, history).ConfigureAwait(false);
    summary.AppendLine(row);
    tables.Append(table);
}

report.AppendLine("### Summary");
report.AppendLine();
report.Append(summary);
report.AppendLine();
report.Append(tables);

SemanticDetectorBase[] securityDetectors =
[
    new PromptInjectionDetector(options),
    new JailbreakDetector(options),
    new IndirectInjectionDetector(options),
];
var spotCheck = new SecuritySpotCheck(generator, evaluator.Failures, ct);
var securityPhrases = Phrase.Load(securityPath);
if (tuning) securityPhrases = [.. securityPhrases.Where(p => !p.IsHeldOut)];
Phrase[] securityRows = [.. securityPhrases, .. everyday];
var securitySummary = new StringBuilder();
securitySummary.AppendLine("| Detector | High / Medium / Low threshold | Lowest positive, High set | Highest benign, High set | Highest benign, Medium set | Positives at High / Medium / Low / missed | Benign at High / Medium / Low | Rule's thresholds on fit: positives at High / Medium / missed | Lowest fit positive, any set | Fit benign at or above it |");
securitySummary.AppendLine("|---|---|---|---|---|---|---|---|---|---|");
var securityTables = new StringBuilder();
foreach (var detector in securityDetectors)
{
    var (row, table) = await spotCheck.EvaluateAsync(detector, securityRows).ConfigureAwait(false);
    securitySummary.AppendLine(row);
    securityTables.Append(table);
}

report.AppendLine(CultureInfo.InvariantCulture, $"## Security spot-check: {model.Name}");
report.AppendLine();
report.Append(securitySummary);
report.AppendLine();
report.Append(securityTables);

var apiKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY");
using var judgeClient = string.IsNullOrWhiteSpace(apiKey)
    ? null
    : new OpenAICompatibleChatClient(new Uri("https://api.anthropic.com/v1/chat/completions"), judgeModel, apiKey);
var scope = EmbeddingScope.Resolve(options, inherited: null)!;
var judge = judgeClient is null ? null : new LlmJudgeReviewer(judgeClient);
var reviewEvaluation = new ReviewEvaluation(scope, judge, toolMessages: false, ct);
var securityReviewEvaluation = new ReviewEvaluation(scope, judge, toolMessages: true, ct);

if (tuning)
{
    report.AppendLine("Tuning mode: held-out phrases are not scored.");
    report.AppendLine();
}
else
{
    report.AppendLine(CultureInfo.InvariantCulture, $"## Held-out review: {model.Name}");
    report.AppendLine();
    report.AppendLine("Configurations: 1 is embeddings alone and uncapped, today's behaviour; 2 caps the embedding result at Medium; 3 adds the LLM judge to 2. Only phrases marked `heldout` are scored. Added ms is the wall time of configuration 3 minus that of configuration 2 for the same phrase. Configuration 3 reviews run under a 30 s measurement timeout, so a slow judge answer is still recorded; beneath each table, the reviews over the hook CLIs' 3 s default and over the library's 5 s default `ReviewTimeout` are counted, and each review over 3 s is named.");
    report.AppendLine();
    if (judgeClient is null) report.AppendLine("Judge columns skipped: ANTHROPIC_API_KEY not set.");
    else report.AppendLine(CultureInfo.InvariantCulture, $"Judge: `{judgeModel}` through the Anthropic OpenAI-compatible endpoint.");
    report.AppendLine();
    if (phrases.Concat(securityPhrases).All(p => !p.IsHeldOut))
    {
        report.AppendLine("No held-out phrases yet: every phrase is `fit`, so the tables below are empty.");
        report.AppendLine();
    }

    foreach (var detector in detectors) report.Append(await reviewEvaluation.EvaluateAsync(detector, phrases).ConfigureAwait(false));
    foreach (var detector in securityDetectors) report.Append(await securityReviewEvaluation.EvaluateAsync(detector, securityPhrases).ConfigureAwait(false));
}

// Benign texts keep the role they are scored with above: compliance texts as user messages, security texts as tool output.
SemanticDetectorBase[] allDetectors = [.. detectors, .. securityDetectors];
(string Text, bool Tool)[] BudgetTexts(bool heldOut) =>
[
    .. everyday.Where(p => p.IsHeldOut == heldOut).Select(p => (p.Text, false)),
    .. compliancePhrases.Where(p => !p.IsPositive && p.IsHeldOut == heldOut).Select(p => (p.Text, false)),
    .. securityPhrases.Where(p => !p.IsPositive && p.IsHeldOut == heldOut).Select(p => (p.Text, true)),
];
report.Append(await ReviewEvaluation.FullPipelineAsync(scope, allDetectors, BudgetTexts(heldOut: false), "Full-pipeline review budget: fit", ct).ConfigureAwait(false));
if (!tuning)
{
    report.Append(await ReviewEvaluation.FullPipelineAsync(scope, allDetectors, BudgetTexts(heldOut: true), "Full-pipeline review budget: held-out", ct).ConfigureAwait(false));
}

var judgeFailures = reviewEvaluation.JudgeFailures + securityReviewEvaluation.JudgeFailures;
if (judgeFailures > 0)
{
    report.AppendLine(CultureInfo.InvariantCulture,
        $"**WARNING: {judgeFailures} reviews failed or timed out; the judge columns are not valid.**");
    report.AppendLine();
}

// Reported only: judge output is not deterministic, so configuration 3 never fails the run.
var judgedHighs = reviewEvaluation.JudgedHighs.Concat(securityReviewEvaluation.JudgedHighs).ToArray();
if (judgedHighs.Length > 0)
{
    report.AppendLine("### Configuration 3 reached High on a legitimate request");
    report.AppendLine();
    foreach (var line in judgedHighs) report.AppendLine(CultureInfo.InvariantCulture, $"- {line}");
    report.AppendLine();
}

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
