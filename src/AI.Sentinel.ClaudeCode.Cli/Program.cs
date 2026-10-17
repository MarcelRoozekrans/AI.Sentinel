using System.Text.Json;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Embeddings;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Configuration;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.Audit;
using AI.Sentinel.Sqlite.Local;
using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.ClaudeCode.Cli;

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
            // which Claude Code treats as a tool failure, not a Sentinel block.
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
            await stderr.WriteAsync("Usage: sentinel-hook <user-prompt-submit|pre-tool-use|post-tool-use>\n").ConfigureAwait(false);
            return 1;
        }

        var (input, parseExit) = await ReadInputAsync(stdin, stderr).ConfigureAwait(false);
        if (input is null) return parseExit;

        var config = HookConfig.FromEnvironment(BuildHookEnvVars());

        var (approvalConfig, configExit) = await TryLoadApprovalConfigAsync(stderr).ConfigureAwait(false);
        if (configExit is { } code) return code;

        // A caller-supplied generator wins; otherwise read SENTINEL_EMBEDDING_* so the hook can do
        // semantic detection at all. A misconfigured setting is reported rather than leaving SEC-01
        // and SEC-05 quietly inert, which is the failure this whole feature removes.
        string? embeddingError = null;
        using var embeddings = embeddingGenerator is null
            ? SentinelEmbeddingSetup.TryCreateFromEnvironment(ReadEnvironment(), out embeddingError)
            : null;
        if (embeddingError is not null)
        {
            await stderr.WriteLineAsync(embeddingError).ConfigureAwait(false);
        }

        var audit = OpenAudit(out var auditProblems);
        await using var _audit = audit.ConfigureAwait(false);

        var provider = BuildProvider(embeddingGenerator ?? embeddings?.Generator, approvalConfig, embeddings?.ExampleCache, message => stderr.WriteLine(message), audit);
        await using var _ = provider.ConfigureAwait(false);

        var adapter = new HookAdapter(provider, config);
        var output = await adapter.HandleAsync(evt, input, default).ConfigureAwait(false);

        var outputJson = JsonSerializer.Serialize(output, HookJsonContext.Default.HookOutput);
        await stdout.WriteAsync(outputJson).ConfigureAwait(false);

        if (config.Verbose)
        {
            await EmitVerboseAsync(stderr, "sentinel-hook", args[0], input.SessionId, output).ConfigureAwait(false);
        }

        // On Block and Warn stderr carries the reason fed back to the model, so audit and semantic
        // diagnostics stay off it. An audit failure never changes the decision.
        var allowed = output.Decision == HookDecision.Allow;
        var reported = await FlushAndReportAuditAsync(audit, auditProblems, config.Verbose || allowed, stderr).ConfigureAwait(false);
        if (allowed && evt == HookEvent.UserPromptSubmit && !config.SuppressSemanticWarning
            && provider.DescribeInertSemanticDetection() is { } semanticWarning)
        {
            await stderr.WriteLineAsync(semanticWarning).ConfigureAwait(false);
        }

        var exit = await ExitCodeAsync(stderr, output).ConfigureAwait(false);
        await CloseAuditAsync(audit, reported, config.Verbose, stderr).ConfigureAwait(false);
        return exit;
    }

    /// <summary>Every hook process records to the shared local audit file unless
    /// <c>SENTINEL_HOOK_AUDIT_SQLITE=off</c>. Opening never throws for an unusable path; settings
    /// problems are returned in <paramref name="problems"/> and session problems are on the result.</summary>
    private static LocalAuditSession OpenAudit(out List<string> problems)
    {
        problems = [];
        var settings = LocalAudit.ReadSettings(BuildHookEnvVars(), "SENTINEL_HOOK_", LocalAudit.DefaultDatabasePath(), problems);
        return LocalAudit.Open(settings, AuditSources.ClaudeCode);
    }

    /// <summary>Entries are forwarded on background tasks; wait (bounded) so an NDJSON line is on disk
    /// before the process exits, then report the problems when <paramref name="report"/> allows.</summary>
    private static async Task<int> FlushAndReportAuditAsync(
        LocalAuditSession audit, List<string> settingsProblems, bool report, TextWriter stderr)
    {
        await audit.FlushAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        if (!report) return int.MaxValue;
        var seen = audit.Problems.Count;
        settingsProblems.AddRange(audit.Problems);
        foreach (var problem in settingsProblems)
        {
            await stderr.WriteLineAsync($"[sentinel-hook] audit: {problem}").ConfigureAwait(false);
        }

        return seen;
    }

    /// <summary>Disposes the audit session. With verbose on, reports problems raised while closing it
    /// that <see cref="FlushAndReportAuditAsync"/> has not already printed.</summary>
    private static async Task CloseAuditAsync(LocalAuditSession audit, int alreadyReported, bool verbose, TextWriter stderr)
    {
        await audit.DisposeAsync().ConfigureAwait(false);
        if (!verbose) return;
        var closing = audit.Problems;
        for (var i = alreadyReported; i < closing.Count; i++)
        {
            await stderr.WriteLineAsync($"[sentinel-hook] audit: {closing[i]}").ConfigureAwait(false);
        }
    }

    private static async Task<int> ExitCodeAsync(TextWriter stderr, HookOutput output) =>
        output.Decision switch
        {
            HookDecision.Block => await WriteReasonAndReturn(stderr, output.Reason, exitCode: 2).ConfigureAwait(false),
            HookDecision.Warn => await WriteReasonAndReturn(stderr, output.Reason, exitCode: 0).ConfigureAwait(false),
            _ => 0,
        };

    private static async Task<(HookInput? Input, int Exit)> ReadInputAsync(TextReader stdin, TextWriter stderr)
    {
        try
        {
            var json = await stdin.ReadToEndAsync().ConfigureAwait(false);
            var input = JsonSerializer.Deserialize(json, HookJsonContext.Default.HookInput)
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

    /// <summary>Embedding settings do not carry the SENTINEL_HOOK_ prefix that BuildHookEnvVars
    /// filters on, so they are read separately.</summary>
    private static Dictionary<string, string?> ReadEnvironment()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key && key.StartsWith("SENTINEL_EMBEDDING_", StringComparison.Ordinal))
            {
                env[key] = entry.Value as string;
            }
        }

        return env;
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
    internal static ServiceProvider BuildProvider(
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator,
        ApprovalConfig? approvalConfig,
        IEmbeddingCache? exampleEmbeddingCache = null,
        Action<string>? detectorFailureSink = null,
        LocalAuditSession? audit = null)
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
            // Compliance findings warn instead of following the High-to-Block mapping.
            opts.AlertOnComplianceFindings();
            opts.EmbeddingGenerator = embeddingGenerator;
            // Without this the hook re-embeds every detector's example phrases on every invocation.
            opts.ExampleEmbeddingCache = exampleEmbeddingCache;
            // No logging provider here, so a detector that fails would degrade silently.
            opts.OnDetectorFailure = detectorFailureSink;
            if (approvalConfig is not null)
                ApprovalBackendSelector.Configure(opts, approvalConfig);
        });

        // Last registration wins for IAuditStore, so these go after AddAISentinel's in-memory default.
        if (audit is not null)
        {
            services.AddSingleton<IAuditStore>(audit.Store);
            foreach (var forwarder in audit.Forwarders)
                services.AddSingleton<IAuditForwarder>(forwarder);
        }

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
