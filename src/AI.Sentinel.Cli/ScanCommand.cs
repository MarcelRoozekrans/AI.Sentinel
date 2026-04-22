using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;

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

        var cmd = new Command("scan", "Run the AI.Sentinel detector pipeline against a saved conversation.")
        {
            fileArg,
            formatOpt,
            outputOpt,
        };

        cmd.SetAction(async (parseResult, ct) =>
        {
            var file = parseResult.GetRequiredValue(fileArg);
            var format = parseResult.GetValue(formatOpt);
            var output = parseResult.GetValue(outputOpt);

            var stdout = parseResult.InvocationConfiguration.Output;
            var stderr = parseResult.InvocationConfiguration.Error;

            return await RunAsync(file, format, output, stdout, stderr, ct).ConfigureAwait(false);
        });

        return cmd;
    }

    public static async Task<int> RunAsync(
        string file,
        ConversationFormat format,
        OutputFormat output,
        TextWriter stdout,
        TextWriter stderr,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        try
        {
            var conversation = await ConversationLoader.LoadAsync(file, format, ct).ConfigureAwait(false);
            var replayResponses = conversation.Turns.Select(t => t.Response).ToArray();
            var replayClient = new SentinelReplayClient(replayResponses);

            var services = new ServiceCollection();
            services.AddAISentinel(opts =>
            {
                // Forensics contract: route every severity through the failure path so
                // ReplayRunner captures each detection. Log would suppress them.
                opts.OnCritical = SentinelAction.Quarantine;
                opts.OnHigh = SentinelAction.Quarantine;
                opts.OnMedium = SentinelAction.Quarantine;
                opts.OnLow = SentinelAction.Quarantine;
            });
            var provider = services.BuildServiceProvider();
            await using var _ = provider.ConfigureAwait(false);
            var pipeline = provider.BuildSentinelPipeline(replayClient);

            var result = await ReplayRunner.RunAsync(file, conversation, pipeline, ct).ConfigureAwait(false);

            var text = output == OutputFormat.Json
                ? JsonFormatter.Format(result)
                : TextFormatter.Format(result);
            await stdout.WriteAsync(text).ConfigureAwait(false);

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
}
