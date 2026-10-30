using System.Text.Json;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Embeddings;
using AI.Sentinel.Review;
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
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null,
        IDetectionReviewer? reviewer = null)
    {
        if (args.Length < 1 || !TryParseEvent(args[0], out var evt))
        {
            await stderr.WriteAsync("Usage: sentinel-hook <user-prompt-submit|pre-tool-use|post-tool-use>\n").ConfigureAwait(false);
            return 1;
        }

        try
        {
            return await RunCoreAsync(args, evt, stdin, stdout, stderr, embeddingGenerator, reviewer).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Fails closed on PreToolUse: a tool call the hook could not evaluate is blocked with exit 2 and the
            // error as the reason. On the other events exit 1 reports the error, and Claude Code goes on without
            // treating it as a block. RunCoreAsync blocks, and audits, a failure once the audit session is open;
            // this catches what fails before that.
            if (evt == HookEvent.PreToolUse)
            {
                return await WriteReasonAndReturn(stderr, HookInternalError.Reason(ex), exitCode: 2).ConfigureAwait(false);
            }

            await stderr.WriteAsync($"Internal error: {ex.GetType().Name}: {ex.Message}\n").ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(
        string[] args, HookEvent evt, TextReader stdin, TextWriter stdout, TextWriter stderr,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null,
        IDetectionReviewer? reviewer = null)
    {
        var hookEnv = BuildHookEnvVars();
        var config = HookConfig.FromEnvironment(hookEnv);

        // Opened before anything below can fail, so a PreToolUse blocked for an internal error is recorded too.
        var audit = OpenAudit(out var auditProblems);
        await using var _audit = audit.ConfigureAwait(false);

        // Sentinel cannot evaluate a call it cannot read, so unreadable input blocks a PreToolUse too.
        var (input, inputError) = await ReadInputAsync(stdin).ConfigureAwait(false);
        if (input is null)
        {
            if (evt == HookEvent.PreToolUse)
            {
                return await BlockOnInternalErrorAsync(
                    args, toolName: null, sessionId: string.Empty, HookInternalError.StdinReason(inputError!), audit, auditProblems, config.Verbose, stderr).ConfigureAwait(false);
            }

            await stderr.WriteAsync(StdinError(inputError!)).ConfigureAwait(false);
            return 1;
        }

        // A config that fails to load must not quietly drop every approval rule, so on PreToolUse it blocks.
        var (approvalConfig, configPath, configError) = TryLoadApprovalConfig();
        if (configError is not null)
        {
            if (evt == HookEvent.PreToolUse)
            {
                return await BlockOnInternalErrorAsync(
                    args, input.ToolName, input.SessionId, HookInternalError.ApprovalConfigReason(configPath!, configError),
                    audit, auditProblems, config.Verbose, stderr).ConfigureAwait(false);
            }

            await stderr.WriteAsync($"Failed to load approval config from '{configPath}': {configError.Message}\n").ConfigureAwait(false);
            return 1;
        }

        HookOutput output;
        string? semanticWarning;
        try
        {
            (output, semanticWarning) = await EvaluateAsync(
                evt, input, config, hookEnv, approvalConfig, audit, stderr, embeddingGenerator, reviewer).ConfigureAwait(false);
        }
        catch (Exception ex) when (evt == HookEvent.PreToolUse)
        {
            return await BlockOnInternalErrorAsync(
                args, input.ToolName, input.SessionId, HookInternalError.Reason(ex), audit, auditProblems, config.Verbose, stderr).ConfigureAwait(false);
        }

        return await WriteDecisionAsync(args, evt, input, output, semanticWarning, config, audit, auditProblems, stdout, stderr).ConfigureAwait(false);
    }

    /// <summary>Writes the decision: the verbose line, audit problems, the semantic warning, the reason and the
    /// wire output. The decision is final here, because the provider is already disposed and nothing below can
    /// turn it into an internal-error block, so the wire output on stdout always matches the exit code.</summary>
    private static async Task<int> WriteDecisionAsync(
        string[] args, HookEvent evt, HookInput input, HookOutput output, string? semanticWarning, HookConfig config,
        LocalAuditSession audit, List<string> auditProblems, TextWriter stdout, TextWriter stderr)
    {
        if (config.Verbose)
        {
            await EmitVerboseAsync(stderr, "sentinel-hook", args[0], input.SessionId, output).ConfigureAwait(false);
        }

        // Only a Block that exits 2, on UserPromptSubmit or PreToolUse, puts its reason on stderr, which is fed
        // back to the model, so audit and semantic diagnostics stay off it then. A Warn goes to stdout's
        // systemMessage and a PostToolUse Block to stdout's decision, so they leave stderr free, as Allow does.
        // An audit failure never changes the decision.
        var reasonOnStderr = BlocksWithExitTwo(evt, output);
        var reported = await FlushAndReportAuditAsync(audit, auditProblems, config.Verbose || !reasonOnStderr, stderr).ConfigureAwait(false);
        if (semanticWarning is not null)
        {
            await stderr.WriteLineAsync(semanticWarning).ConfigureAwait(false);
        }

        var exit = await ExitCodeAsync(stderr, evt, output).ConfigureAwait(false);
        await WriteWireOutputAsync(stdout, evt, output).ConfigureAwait(false);
        await CloseAuditAsync(audit, reported, config.Verbose, stderr).ConfigureAwait(false);
        return exit;
    }

    /// <summary>Scans the input and takes the decision. The provider and the embedding generator are disposed
    /// before this returns, so a failure while disposing them is still an internal error, before any output is
    /// written. Returns the startup warning on Allow of a prompt: that semantic detection is inert, or that its
    /// detections are capped because nothing reviews them.</summary>
    private static async Task<(HookOutput Output, string? SemanticWarning)> EvaluateAsync(
        HookEvent evt, HookInput input, HookConfig config, Dictionary<string, string?> hookEnv, ApprovalConfig? approvalConfig,
        LocalAuditSession audit, TextWriter stderr, IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator,
        IDetectionReviewer? reviewer)
    {
        // A caller-supplied generator wins; otherwise read SENTINEL_EMBEDDING_* so the hook can do
        // semantic detection at all. A misconfigured setting is reported rather than leaving SEC-01
        // and SEC-05 quietly inert, which is the failure this whole feature removes.
        var environment = ReadEnvironment();
        string? embeddingError = null;
        using var embeddings = embeddingGenerator is null
            ? SentinelEmbeddingSetup.TryCreateFromEnvironment(environment, out embeddingError)
            : null;
        if (embeddingError is not null)
        {
            await stderr.WriteLineAsync(embeddingError).ConfigureAwait(false);
        }

        // Without a reviewer a semantic hit is capped at Medium, so the hook can only warn on it. A misconfigured
        // setting is reported by name for the same reason as the embedding one.
        string? reviewError = null;
        using var review = reviewer is null
            ? SentinelReviewSetup.TryCreateFromEnvironment(environment, out reviewError)
            : null;
        if (reviewError is not null)
        {
            await stderr.WriteLineAsync(reviewError).ConfigureAwait(false);
        }

        var provider = BuildProvider(embeddingGenerator ?? embeddings?.Generator, approvalConfig, embeddings?.ExampleCache, message => stderr.WriteLine(message), audit,
            reviewer: reviewer ?? review?.Reviewer, reviewLimits: ReviewLimitsFor(review),
            enableComplianceDetectors: config.EnableComplianceDetectors, detectors: DetectorPresets.Parse(hookEnv.GetValueOrDefault("SENTINEL_HOOK_DETECTORS")));
        await using var _ = provider.ConfigureAwait(false);

        var adapter = new HookAdapter(provider, config);
        var output = await adapter.HandleAsync(evt, input, default).ConfigureAwait(false);
        var semanticWarning = output.Decision == HookDecision.Allow && evt == HookEvent.UserPromptSubmit && !config.SuppressSemanticWarning
            ? CombineWarnings(provider.DescribeInertSemanticDetection(), provider.DescribeUnreviewedSemanticDetection())
            : null;
        return (output, semanticWarning);
    }

    /// <summary>Blocks a PreToolUse the hook could not evaluate: exit 2 with <paramref name="reason"/> on stderr, and
    /// an <c>AUTHZ-DENY</c> entry with the <c>internal_error</c> code, written best effort. With verbose on it writes
    /// the usual diagnostic line; audit problems are reported only then, as for any Block that exits 2.</summary>
    private static async Task<int> BlockOnInternalErrorAsync(
        string[] args, string? toolName, string sessionId, string reason,
        LocalAuditSession audit, List<string> auditProblems, bool verbose, TextWriter stderr)
    {
        if (await HookInternalError.TryAuditAsync(audit.Store, audit.Forwarders, toolName, sessionId, reason).ConfigureAwait(false) is { } problem)
        {
            auditProblems.Add(problem);
        }

        if (verbose)
        {
            // No reason passed: the diagnostic parses a detector and severity from it, and this block has neither.
            await EmitVerboseAsync(stderr, "sentinel-hook", args[0], sessionId, new HookOutput { Decision = HookDecision.Block }).ConfigureAwait(false);
        }

        var reported = await FlushAndReportAuditAsync(audit, auditProblems, verbose, stderr).ConfigureAwait(false);
        var exit = await WriteReasonAndReturn(stderr, reason, exitCode: 2).ConfigureAwait(false);
        await CloseAuditAsync(audit, reported, verbose, stderr).ConfigureAwait(false);
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

    /// <summary>Writes the documented Claude Code hook output to stdout; a Block that exits 2 writes none.</summary>
    private static async Task WriteWireOutputAsync(TextWriter stdout, HookEvent evt, HookOutput output)
    {
        if (ClaudeCodeWireOutput.From(evt, output) is { } wire)
        {
            await stdout.WriteAsync(
                JsonSerializer.Serialize(wire, ClaudeCodeWireJsonContext.Default.ClaudeCodeWireOutput)).ConfigureAwait(false);
        }
    }

    /// <summary>Exit 2 with the reason on stderr for a Block on UserPromptSubmit or PreToolUse, which stops the prompt
    /// or the tool call. Exit 0 otherwise: a PostToolUse Block and a Warn are carried by stdout, and the tool of a
    /// PostToolUse has already run.</summary>
    private static async Task<int> ExitCodeAsync(TextWriter stderr, HookEvent evt, HookOutput output) =>
        BlocksWithExitTwo(evt, output)
            ? await WriteReasonAndReturn(stderr, output.Reason, exitCode: 2).ConfigureAwait(false)
            : 0;

    private static bool BlocksWithExitTwo(HookEvent evt, HookOutput output) =>
        output.Decision == HookDecision.Block && evt != HookEvent.PostToolUse;

    /// <summary>Reads and parses the hook input. A failure is returned rather than written, because its message
    /// depends on the event: on PreToolUse it is the reason for an internal-error block.</summary>
    private static async Task<(HookInput? Input, Exception? Error)> ReadInputAsync(TextReader stdin)
    {
        try
        {
            var json = await stdin.ReadToEndAsync().ConfigureAwait(false);
            var input = JsonSerializer.Deserialize(json, HookJsonContext.Default.HookInput)
                ?? throw new InvalidDataException("Empty input.");
            return (input, null);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        {
            return (null, ex);
        }
    }

    /// <summary>The stdin error on an event that does not block on it.</summary>
    private static string StdinError(Exception error) =>
        error is JsonException ? $"Error: malformed stdin JSON: {error.Message}\n" : $"Error: {error.Message}\n";

    /// <summary>Embedding and review settings do not carry the SENTINEL_HOOK_ prefix that BuildHookEnvVars
    /// filters on, so they are read separately.</summary>
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

    /// <summary>A hook runs on the user's critical path, so a review gets 3 s unless
    /// <c>SENTINEL_REVIEW_TIMEOUT_MS</c> says otherwise. The library default is 5 s.</summary>
    internal static ReviewLimits DefaultReviewLimits { get; } = new(MaxPerScan: 4, Timeout: TimeSpan.FromSeconds(3));

    /// <summary>The limits from the review setting, with the hook defaults for what it leaves unset.</summary>
    internal static ReviewLimits ReviewLimitsFor(SentinelReviewSetup? review) =>
        new(review?.MaxReviewsPerScan ?? DefaultReviewLimits.MaxPerScan, review?.ReviewTimeout ?? DefaultReviewLimits.Timeout);

    /// <summary>Joins the warnings that apply, one per line, or returns <see langword="null"/> when none does.</summary>
    private static string? CombineWarnings(params string?[] warnings)
    {
        var present = warnings.Where(w => w is not null).ToArray();
        return present.Length == 0 ? null : string.Join('\n', present);
    }

    private static Dictionary<string, string?> BuildHookEnvVars() =>
        Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .Where(e => e.Key is string key && key.StartsWith("SENTINEL_HOOK_", StringComparison.Ordinal))
            .ToDictionary(e => (string)e.Key, e => e.Value as string, StringComparer.Ordinal);

    /// <summary>Loads <c>SENTINEL_APPROVAL_CONFIG</c> when it is set. A failure of any kind is returned rather than
    /// thrown, with the path, so the caller decides whether it blocks.</summary>
    private static (ApprovalConfig? Config, string? Path, Exception? Error) TryLoadApprovalConfig()
    {
        var path = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");
        if (string.IsNullOrWhiteSpace(path)) return (null, null, null);
        try
        {
            return (ApprovalConfigLoader.Load(path), path, null);
        }
#pragma warning disable CA1031 // Every load failure is reported; on PreToolUse it blocks the call.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return (null, path, ex);
        }
    }

    /// <summary>
    /// Builds the DI provider with optional approval bindings. Backend stores must be registered
    /// BEFORE <c>AddAISentinel</c>: when bindings carry an <see cref="ApprovalSpec"/> and no
    /// <see cref="IApprovalStore"/> is yet registered, <c>AddAISentinel</c> auto-registers
    /// <see cref="InMemoryApprovalStore"/> — the Sqlite/EntraPim DI extensions throw on duplicate
    /// registration, so they must be wired first. <paramref name="detectors"/> then narrows the detectors
    /// <c>AddAISentinel</c> registered; see <see cref="DetectorPresets.UseDetectorPreset"/>. It defaults to the security
    /// preset: the response-quality detectors judge a model's reply, and a hook never sees one (#450).
    /// </summary>
    internal static ServiceProvider BuildProvider(
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator,
        ApprovalConfig? approvalConfig,
        IEmbeddingCache? exampleEmbeddingCache = null,
        Action<string>? detectorFailureSink = null,
        LocalAuditSession? audit = null,
        bool enableComplianceDetectors = false,
        DetectorPreset detectors = DetectorPreset.Security,
        IDetectionReviewer? reviewer = null,
        ReviewLimits? reviewLimits = null)
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
            // The compliance detectors are opt-in (SENTINEL_HOOK_COMPLIANCE=on). When on, their findings warn
            // instead of following the High-to-Block mapping.
            if (enableComplianceDetectors)
                opts.EnableComplianceDetectors();
            opts.AlertOnComplianceFindings();
            opts.EmbeddingGenerator = embeddingGenerator;
            // Without this the hook re-embeds every detector's example phrases on every invocation.
            opts.ExampleEmbeddingCache = exampleEmbeddingCache;
            // No logging provider here, so a detector that fails would degrade silently.
            opts.OnDetectorFailure = detectorFailureSink;
            var limits = reviewLimits ?? DefaultReviewLimits;
            opts.Reviewer = reviewer;
            opts.MaxReviewsPerScan = limits.MaxPerScan;
            opts.ReviewTimeout = limits.Timeout;
            if (approvalConfig is not null)
                ApprovalBackendSelector.Configure(opts, approvalConfig);
        });

        services.UseDetectorPreset(detectors);

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

        // An internal-error reason names no detector, so it is not parsed for one.
        if (output.Decision != HookDecision.Allow && !string.IsNullOrEmpty(output.Reason)
            && !output.Reason.StartsWith(HookInternalError.Prefix, StringComparison.Ordinal))
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
