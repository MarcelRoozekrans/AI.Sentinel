using System.CommandLine;
using AI.Sentinel.Detection;

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

        var cmd = new Command("scan", "Run the AI.Sentinel detector pipeline against a saved conversation.")
        {
            fileArg,
            formatOpt,
            outputOpt,
            expectOpt,
            minSevOpt,
            baselineOpt,
        };

        cmd.SetAction(async (parseResult, ct) =>
        {
            var file = parseResult.GetRequiredValue(fileArg);
            var format = parseResult.GetValue(formatOpt);
            var output = parseResult.GetValue(outputOpt);
            var expected = parseResult.GetValue(expectOpt) ?? [];
            var minSev = parseResult.GetValue(minSevOpt);
            var baseline = parseResult.GetValue(baselineOpt);

            var stdout = parseResult.InvocationConfiguration.Output;
            var stderr = parseResult.InvocationConfiguration.Error;

            return await RunAsync(file, format, output, stdout, stderr, ct,
                expected, minSev, baseline).ConfigureAwait(false);
        });

        return cmd;
    }

    public static async Task<int> RunAsync(
        string file,
        ConversationFormat format,
        OutputFormat output,
        TextWriter stdout,
        TextWriter stderr,
        CancellationToken ct,
        IReadOnlyList<string>? expectedDetectors = null,
        Severity? minSeverity = null,
        string? baselinePath = null)
    {
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        try
        {
            var conversation = await ConversationLoader.LoadAsync(file, format, ct).ConfigureAwait(false);
            var replayResponses = conversation.Turns.Select(t => t.Response).ToArray();
            var replayClient = new SentinelReplayClient(replayResponses);

            var (provider, pipeline) = ForensicsPipelineFactory.Build(replayClient);
            await using var _ = provider.ConfigureAwait(false);

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
