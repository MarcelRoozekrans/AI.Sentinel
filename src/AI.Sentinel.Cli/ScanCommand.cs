using System.CommandLine;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Embeddings;
using AI.Sentinel.Review;

namespace AI.Sentinel.Cli;

public static class ScanCommand
{
    public static Command Build()
    {
        var fileArg = new Argument<string>("file")
        {
            Description = "Path to the conversation file (OpenAI JSON or AI.Sentinel audit NDJSON).",
        };
        var formatOpt = new Option<ConversationFormat>("--format")
        {
            Description = "Conversation format.",
            DefaultValueFactory = _ => ConversationFormat.Auto,
        };
        var outputOpt = new Option<OutputFormat>("--output")
        {
            Description = "Output format.",
            DefaultValueFactory = _ => OutputFormat.Text,
        };
        var expectOpt = new Option<string[]>("--expect")
        {
            Description = "Detector IDs that must fire (repeatable).",
            AllowMultipleArgumentsPerToken = true,
        };
        var minSevOpt = new Option<Severity?>("--min-severity")
        {
            Description = "Minimum required max severity.",
        };
        var baselineOpt = new Option<string?>("--baseline")
        {
            Description = "Path to a prior ReplayResult JSON for regression comparison.",
        };

        var complianceOpt = ComplianceOption();
        var cmd = new Command("scan", "Run the AI.Sentinel detector pipeline against a saved conversation.")
        {
            fileArg,
            formatOpt,
            outputOpt,
            expectOpt,
            minSevOpt,
            baselineOpt,
            complianceOpt,
        };

        cmd.SetAction(async (parseResult, ct) =>
        {
            var file = parseResult.GetRequiredValue(fileArg);
            var format = parseResult.GetValue(formatOpt);
            var output = parseResult.GetValue(outputOpt);
            var expected = parseResult.GetValue(expectOpt) ?? [];
            var minSev = parseResult.GetValue(minSevOpt);
            var baseline = parseResult.GetValue(baselineOpt);
            var compliance = parseResult.GetValue(complianceOpt);

            var stdout = parseResult.InvocationConfiguration.Output;
            var stderr = parseResult.InvocationConfiguration.Error;

            return await RunAsync(file, format, output, stdout, stderr, ct,
                expected, minSev, baseline, enableComplianceDetectors: compliance).ConfigureAwait(false);
        });

        return cmd;
    }

    private static Option<bool> ComplianceOption() => new("--compliance")
    {
        Description = "Also run the opt-in Art. 5 compliance detectors CMP-01 to CMP-04. SENTINEL_HOOK_COMPLIANCE=on does the same.",
    };

    public static async Task<int> RunAsync(
        string file,
        ConversationFormat format,
        OutputFormat output,
        TextWriter stdout,
        TextWriter stderr,
        CancellationToken ct,
        IReadOnlyList<string>? expectedDetectors = null,
        Severity? minSeverity = null,
        string? baselinePath = null,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null,
        bool enableComplianceDetectors = false,
        IDetectionReviewer? reviewer = null)
    {
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        try
        {
            var conversation = await ConversationLoader.LoadAsync(file, format, ct).ConfigureAwait(false);
            var replayResponses = conversation.Turns.Select(t => t.Response).ToArray();
            var replayClient = new SentinelReplayClient(replayResponses);

            var environment = ReadEnvironment();
            using var embeddings = await ResolveEmbeddingsAsync(embeddingGenerator, environment, stderr).ConfigureAwait(false);
            using var review = await ResolveReviewAsync(reviewer, environment, stderr).ConfigureAwait(false);

            var (provider, pipeline) = ForensicsPipelineFactory.Build(
                replayClient, embeddingGenerator ?? embeddings?.Generator, embeddings?.ExampleCache,
                message => stderr.WriteLine(message),
                enableComplianceDetectors || ComplianceFromEnvironment(),
                reviewer ?? review?.Reviewer, review?.MaxReviewsPerScan, review?.ReviewTimeout);
            await using var _ = provider.ConfigureAwait(false);

            // No logging provider is registered here, so the library's ILogger warning reaches nobody.
            // Without this, a scan of a conversation containing a textbook injection reports Clean and
            // gives no hint that the detectors for it never ran (#170).
            if (!SuppressSemanticWarning())
            {
                await WriteSemanticWarningsAsync(provider, stderr).ConfigureAwait(false);
            }

            var result = await ReplayRunner.RunAsync(file, conversation, pipeline, ct).ConfigureAwait(false);

            var text = output == OutputFormat.Json
                ? JsonFormatter.Format(result)
                : TextFormatter.Format(result);
            await stdout.WriteAsync(text).ConfigureAwait(false);

            var (assertionsPassed, assertionFailures) = AssertionEvaluator.Evaluate(
                result, expectedDetectors ?? [], minSeverity);
            foreach (var f in assertionFailures)
            {
                await stderr.WriteAsync($"Assertion failed: {f}\n").ConfigureAwait(false);
            }

            var baselineHasRegression = baselinePath is not null
                && await ApplyBaselineAsync(baselinePath, result, stdout, ct).ConfigureAwait(false);

            if (!assertionsPassed || baselineHasRegression) return 1;
            return 0;
        }
        catch (FileNotFoundException ex)
        {
            await stderr.WriteAsync($"Error: {ex.Message}\n").ConfigureAwait(false);
            return 2;
        }
        catch (InvalidDataException ex)
        {
            await stderr.WriteAsync($"Error: {ex.Message}\n").ConfigureAwait(false);
            return 2;
        }
    }

    /// <summary>A caller-supplied generator wins; otherwise read SENTINEL_EMBEDDING_* so a scan can
    /// use semantic detection instead of silently reporting Clean for what it cannot see.</summary>
    private static async Task<SentinelEmbeddingSetup?> ResolveEmbeddingsAsync(
        IEmbeddingGenerator<string, Embedding<float>>? supplied, IReadOnlyDictionary<string, string?> environment, TextWriter stderr)
    {
        if (supplied is not null) return null;

        var setup = SentinelEmbeddingSetup.TryCreateFromEnvironment(environment, out var error);
        if (error is not null)
        {
            await stderr.WriteLineAsync(error).ConfigureAwait(false);
        }

        return setup;
    }

    /// <summary>The inert warning when no generator is configured, and the unreviewed one when semantic detections
    /// are capped at Medium with no reviewer to lift the cap.</summary>
    private static async Task WriteSemanticWarningsAsync(IServiceProvider provider, TextWriter stderr)
    {
        if (provider.DescribeInertSemanticDetection() is { } inertWarning)
        {
            await stderr.WriteLineAsync(inertWarning).ConfigureAwait(false);
        }

        if (provider.DescribeUnreviewedSemanticDetection() is { } unreviewedWarning)
        {
            await stderr.WriteLineAsync(unreviewedWarning).ConfigureAwait(false);
        }
    }

    /// <summary>A caller-supplied reviewer wins; otherwise read SENTINEL_REVIEW_*. Without a reviewer a semantic
    /// detection is capped at Medium, so a scan cannot report it as High. A bad setting is reported by name.</summary>
    private static async Task<SentinelReviewSetup?> ResolveReviewAsync(
        IDetectionReviewer? supplied, IReadOnlyDictionary<string, string?> environment, TextWriter stderr)
    {
        if (supplied is not null) return null;

        var setup = SentinelReviewSetup.TryCreateFromEnvironment(environment, out var error);
        if (error is not null)
        {
            await stderr.WriteLineAsync(error).ConfigureAwait(false);
        }

        return setup;
    }

    /// <summary>Embedding and review settings, read directly because they carry no host-specific prefix.</summary>
    private static Dictionary<string, string?> ReadEnvironment()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key && (key.StartsWith("SENTINEL_EMBEDDING_", StringComparison.Ordinal)
                || key.StartsWith("SENTINEL_REVIEW_", StringComparison.Ordinal)))
            {
                env[key] = entry.Value as string;
            }
        }

        return env;
    }

    /// <summary><c>SENTINEL_HOOK_COMPLIANCE</c>, the switch the hook CLIs use, so one setting turns the
    /// compliance detectors on for the hooks and for a scan that reproduces their findings.</summary>
    private static bool ComplianceFromEnvironment()
    {
        var v = Environment.GetEnvironmentVariable("SENTINEL_HOOK_COMPLIANCE");
        return string.Equals(v, "on", StringComparison.OrdinalIgnoreCase)
            || string.Equals(v, "1", StringComparison.Ordinal)
            || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(v, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static bool SuppressSemanticWarning()
    {
        var v = Environment.GetEnvironmentVariable("SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING");
        return string.Equals(v, "1", StringComparison.Ordinal)
            || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(v, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<bool> ApplyBaselineAsync(
        string baselinePath,
        ReplayResult result,
        TextWriter stdout,
        CancellationToken ct)
    {
        var baselineJson = await File.ReadAllTextAsync(baselinePath, ct).ConfigureAwait(false);
        var baseline = JsonFormatter.Deserialize(baselineJson);
        var (hasRegression, entries) = BaselineDiffer.Diff(baseline, result);
        foreach (var e in entries)
        {
            await stdout.WriteAsync(
                $"Turn {e.TurnIndex + 1}: {e.Kind.ToString().ToUpperInvariant()} - {e.Message}\n")
                .ConfigureAwait(false);
        }
        return hasRegression;
    }
}
