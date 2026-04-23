using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel;
using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.ClaudeCode.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
        => await RunAsync(args, Console.In, Console.Out, Console.Error).ConfigureAwait(false);

    public static async Task<int> RunAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        try
        {
            return await RunCoreAsync(args, stdin, stdout, stderr).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Fail safe: unexpected errors must never produce exit code 2 (Block).
            // Exit code 1 signals "operator error / malformed input" to the host,
            // which Claude Code treats as a tool failure, not a Sentinel block.
            await stderr.WriteAsync($"Internal error: {ex.GetType().Name}: {ex.Message}\n").ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length < 1 || !TryParseEvent(args[0], out var evt))
        {
            await stderr.WriteAsync("Usage: sentinel-hook <user-prompt-submit|pre-tool-use|post-tool-use>\n").ConfigureAwait(false);
            return 1;
        }

        HookInput input;
        try
        {
            var json = await stdin.ReadToEndAsync().ConfigureAwait(false);
            input = JsonSerializer.Deserialize(json, HookJsonContext.Default.HookInput)
                ?? throw new InvalidDataException("Empty input.");
        }
        catch (JsonException ex)
        {
            await stderr.WriteAsync($"Error: malformed stdin JSON: {ex.Message}\n").ConfigureAwait(false);
            return 1;
        }
        catch (InvalidDataException ex)
        {
            await stderr.WriteAsync($"Error: {ex.Message}\n").ConfigureAwait(false);
            return 1;
        }

        var envVars = Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .Where(e => e.Key is string key && key.StartsWith("SENTINEL_HOOK_", StringComparison.Ordinal))
            .ToDictionary(e => (string)e.Key, e => e.Value as string, StringComparer.Ordinal);
        var config = HookConfig.FromEnvironment(envVars);

        var services = new ServiceCollection();
        services.AddAISentinel(opts =>
        {
            opts.OnCritical = SentinelAction.Quarantine;
            opts.OnHigh = SentinelAction.Quarantine;
            opts.OnMedium = SentinelAction.Quarantine;
            opts.OnLow = SentinelAction.Quarantine;
        });
        var provider = services.BuildServiceProvider();
        await using var _ = provider.ConfigureAwait(false);

        var adapter = new HookAdapter(provider, config);
        var output = await adapter.HandleAsync(evt, input, default).ConfigureAwait(false);

        var outputJson = JsonSerializer.Serialize(output, HookJsonContext.Default.HookOutput);
        await stdout.WriteAsync(outputJson).ConfigureAwait(false);

        return output.Decision switch
        {
            HookDecision.Block => await WriteReasonAndReturn(stderr, output.Reason, exitCode: 2).ConfigureAwait(false),
            HookDecision.Warn => await WriteReasonAndReturn(stderr, output.Reason, exitCode: 0).ConfigureAwait(false),
            _ => 0,
        };
    }

    private static async Task<int> WriteReasonAndReturn(TextWriter stderr, string? reason, int exitCode)
    {
        if (!string.IsNullOrEmpty(reason))
            await stderr.WriteAsync($"{reason}\n").ConfigureAwait(false);
        return exitCode;
    }

    private static bool TryParseEvent(string arg, out HookEvent evt)
    {
        evt = default;
        switch (arg)
        {
            case "user-prompt-submit": evt = HookEvent.UserPromptSubmit; return true;
            case "pre-tool-use": evt = HookEvent.PreToolUse; return true;
            case "post-tool-use": evt = HookEvent.PostToolUse; return true;
            default: return false;
        }
    }
}
