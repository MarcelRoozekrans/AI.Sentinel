using System.Text.Json;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Configuration;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Copilot;

namespace AI.Sentinel.Copilot.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
        => await RunAsync(args, Console.In, Console.Out, Console.Error).ConfigureAwait(false);

    public static async Task<int> RunAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null)
    {
        try
        {
            return await RunCoreAsync(args, stdin, stdout, stderr, embeddingGenerator).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Fail safe: unexpected errors must never produce exit code 2 (Block).
            // Exit code 1 signals "operator error / malformed input" to the host,
            // which Copilot treats as a tool failure, not a Sentinel block.
            await stderr.WriteAsync($"Internal error: {ex.GetType().Name}: {ex.Message}\n").ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null)
    {
        if (args.Length < 1 || !TryParseEvent(args[0], out var evt))
        {
            await stderr.WriteAsync("Usage: sentinel-copilot-hook <user-prompt-submitted|pre-tool-use|post-tool-use>\n").ConfigureAwait(false);
            return 1;
        }

        var (input, parseExit) = await ReadInputAsync(stdin, stderr).ConfigureAwait(false);
        if (input is null) return parseExit;

        var config = CopilotHookConfig.FromEnvironment(BuildHookEnvVars());

        var (approvalConfig, configExit) = await TryLoadApprovalConfigAsync(stderr).ConfigureAwait(false);
        if (configExit is { } code) return code;

        var provider = BuildProvider(embeddingGenerator, approvalConfig);
        await using var _ = provider.ConfigureAwait(false);

        var adapter = new CopilotHookAdapter(provider, config);
        var output = await adapter.HandleAsync(evt, input, default).ConfigureAwait(false);

        var outputJson = JsonSerializer.Serialize(output, CopilotHookJsonContext.Default.HookOutput);
        await stdout.WriteAsync(outputJson).ConfigureAwait(false);

        if (config.Verbose)
        {
            await EmitVerboseAsync(stderr, "sentinel-copilot-hook", args[0], input.SessionId, output).ConfigureAwait(false);
        }

        return output.Decision switch
        {
            HookDecision.Block => await WriteReasonAndReturn(stderr, output.Reason, exitCode: 2).ConfigureAwait(false),
            HookDecision.Warn => await WriteReasonAndReturn(stderr, output.Reason, exitCode: 0).ConfigureAwait(false),
            _ => 0,
        };
    }

    private static async Task<(CopilotHookInput? Input, int Exit)> ReadInputAsync(TextReader stdin, TextWriter stderr)
    {
        try
        {
            var json = await stdin.ReadToEndAsync().ConfigureAwait(false);
            var input = JsonSerializer.Deserialize(json, CopilotHookJsonContext.Default.CopilotHookInput)
                ?? throw new InvalidDataException("Empty input.");
            return (input, 0);
        }
        catch (JsonException ex)
        {
            await stderr.WriteAsync($"Error: malformed stdin JSON: {ex.Message}\n").ConfigureAwait(false);
            return (null, 1);
        }
        catch (InvalidDataException ex)
        {
            await stderr.WriteAsync($"Error: {ex.Message}\n").ConfigureAwait(false);
            return (null, 1);
        }
    }

    private static Dictionary<string, string?> BuildHookEnvVars() =>
        Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .Where(e => e.Key is string key && key.StartsWith("SENTINEL_HOOK_", StringComparison.Ordinal))
            .ToDictionary(e => (string)e.Key, e => e.Value as string, StringComparer.Ordinal);

    private static async Task<(ApprovalConfig? Config, int? Exit)> TryLoadApprovalConfigAsync(TextWriter stderr)
    {
        var path = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");
        if (string.IsNullOrWhiteSpace(path)) return (null, null);
        try
        {
            return (ApprovalConfigLoader.Load(path), null);
        }
        catch (Exception ex) when (ex is FileNotFoundException or InvalidOperationException or JsonException)
        {
            await stderr.WriteAsync($"Failed to load approval config from '{path}': {ex.Message}\n").ConfigureAwait(false);
            return (null, 1);
        }
    }

    /// <summary>
    /// Builds the DI provider with optional approval bindings. Backend stores must be registered
    /// BEFORE <c>AddAISentinel</c>: when bindings carry an <see cref="ApprovalSpec"/> and no
    /// <see cref="IApprovalStore"/> is yet registered, <c>AddAISentinel</c> auto-registers
    /// <see cref="InMemoryApprovalStore"/> — the Sqlite/EntraPim DI extensions throw on duplicate
    /// registration, so they must be wired first.
    /// </summary>
    private static ServiceProvider BuildProvider(
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator,
        ApprovalConfig? approvalConfig)
    {
        var services = new ServiceCollection();
        var backendKind = approvalConfig is null
            ? ApprovalBackendKind.None
            : ApprovalBackendSelector.GetBackend(approvalConfig);

        switch (backendKind)
        {
            case ApprovalBackendKind.Sqlite:
                services.AddSentinelSqliteApprovalStore(o => o.DatabasePath = approvalConfig!.DatabasePath!);
                break;
            case ApprovalBackendKind.EntraPim:
                services.AddSentinelEntraPimApprovalStore(o => o.TenantId = approvalConfig!.TenantId!);
                break;
            // None / InMemory: AddAISentinel auto-registers InMemoryApprovalStore when bindings
            // carry an ApprovalSpec.
        }

        services.AddAISentinel(opts =>
        {
            opts.OnCritical = SentinelAction.Quarantine;
            opts.OnHigh = SentinelAction.Quarantine;
            opts.OnMedium = SentinelAction.Quarantine;
            opts.OnLow = SentinelAction.Quarantine;
            opts.EmbeddingGenerator = embeddingGenerator;
            if (approvalConfig is not null)
                ApprovalBackendSelector.Configure(opts, approvalConfig);
        });

        return services.BuildServiceProvider();
    }

    private static async Task<int> WriteReasonAndReturn(TextWriter stderr, string? reason, int exitCode)
    {
        if (!string.IsNullOrEmpty(reason))
            await stderr.WriteAsync($"{reason}\n").ConfigureAwait(false);
        return exitCode;
    }

    private static async Task EmitVerboseAsync(
        TextWriter stderr,
        string toolPrefix,
        string eventName,
        string sessionId,
        HookOutput output)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append('[').Append(toolPrefix).Append(']')
          .Append(" event=").Append(eventName)
          .Append(" decision=").Append(output.Decision);

        if (output.Decision != HookDecision.Allow && !string.IsNullOrEmpty(output.Reason))
        {
            // output.Reason format: "{DetectorId} {Severity}: {text}"
            var space1 = output.Reason.IndexOf(' ', StringComparison.Ordinal);
            var colon = space1 > 0 ? output.Reason.IndexOf(':', space1 + 1) : -1;
            if (space1 > 0 && colon > space1)
            {
                var detectorId = output.Reason[..space1];
                var severity = output.Reason[(space1 + 1)..colon];
                sb.Append(" detector=").Append(detectorId).Append(" severity=").Append(severity);
            }
        }

        sb.Append(" session=").Append(sessionId).Append('\n');
        await stderr.WriteAsync(sb.ToString()).ConfigureAwait(false);
    }

    private static bool TryParseEvent(string arg, out CopilotHookEvent evt)
    {
        evt = default;
        switch (arg)
        {
            case "user-prompt-submitted": evt = CopilotHookEvent.UserPromptSubmitted; return true;
            case "pre-tool-use": evt = CopilotHookEvent.PreToolUse; return true;
            case "post-tool-use": evt = CopilotHookEvent.PostToolUse; return true;
            default: return false;
        }
    }
}
