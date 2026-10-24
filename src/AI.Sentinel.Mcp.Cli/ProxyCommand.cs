using System.Globalization;
using System.Text.Json;
using AI.Sentinel;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Configuration;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp;
using AI.Sentinel.Mcp.Logging;
using AI.Sentinel.Sqlite.Local;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AI.Sentinel.Mcp.Cli;

internal static class ProxyCommand
{
    /// <summary>Parses <c>proxy --target &lt;cmd&gt; [&lt;target-args&gt;...]</c> and runs the proxy.</summary>
    public static Task<int> RunAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr, CancellationToken ct)
        => RunAsync(args, stdin, stdout, stderr, ct, transportFactory: null);

    /// <param name="transportFactory">Test seam: supplies the host and target transports instead of
    /// the process stdio and the <c>--target</c> command.</param>
    internal static async Task<int> RunAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr, CancellationToken ct,
        Func<(ITransport Host, IClientTransport Target)>? transportFactory)
    {
        // args[0] is "proxy" (already matched by Program)
        if (args.Length < 3 || !string.Equals(args[1], "--target", StringComparison.Ordinal))
        {
            await stderr.WriteLineAsync(
                "Usage: sentinel-mcp proxy --target <command> [<target-args>...]"
            ).ConfigureAwait(false);
            return 1;
        }

        var targetCommand = args[2];
        var targetArgs = args.Length > 3 ? args[3..] : Array.Empty<string>();

        var envVars = ReadSentinelEnvironment();
        var config = ResolveHookConfig(args, envVars);
        var preset = ParsePreset(envVars);
        var maxScanBytes = ParseMaxScanBytes(envVars);
        var placeholderIdleExpiry = ParseRedactionIdleExpiry(envVars);

        // Every proxy process records to the shared local audit file unless SENTINEL_MCP_AUDIT_SQLITE=off.
        // Opening never throws; problems are reported on stderr, which is not model-facing here.
        var settingsProblems = new List<string>();
        var settings = LocalAudit.ReadSettings(envVars, "SENTINEL_MCP_", LocalAudit.DefaultDatabasePath(), settingsProblems);
        // Later problems are reported the moment they are recorded, so a killed proxy still reports them.
        var audit = LocalAudit.Open(settings, AuditSources.Mcp, problem => ReportProblem(problem, stderr));
        ServiceProvider? provider = null;
        try
        {
            await ReportProblemsAsync(settingsProblems, stderr).ConfigureAwait(false);

            // Optional approval-config wiring. When SENTINEL_APPROVAL_CONFIG is set, build a guard +
            // approval store so the MCP proxy can gate tool calls behind PIM-style approvals. The
            // SENTINEL_MCP_APPROVAL_WAIT_SEC env var (positive integer) opts into wait-and-block; without
            // it the proxy fails fast with the receipt embedded in the JSON-RPC error. Provider owns
            // the SqliteApprovalStore connection / EntraPim Graph client and must be disposed on
            // shutdown so SQLite WAL/SHM are flushed cleanly. The stack writes approval decisions to
            // the same audit file as the proxy, so the audit session is opened first.
            var (stackProvider, guard, approvalStore, approvalWait, configError) =
                await BuildAuthorizationStackAsync(stderr, audit.Store, audit.Forwarders).ConfigureAwait(false);
            provider = stackProvider;
            if (configError) return 1;

            return await RunProxyAsync(
                targetCommand, targetArgs, config, preset, maxScanBytes, placeholderIdleExpiry,
                stderr, ct, guard, approvalStore, approvalWait, audit, transportFactory).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                await CloseAuditAsync(audit, stderr).ConfigureAwait(false);
            }
            finally
            {
                if (provider is not null) await provider.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Entries are forwarded on background tasks; wait (bounded) so an NDJSON line is on disk
    /// before the process exits, then dispose the session. Problems were already reported as they happened,
    /// including any raised while disposing, which also go out through the callback.</summary>
    private static async Task CloseAuditAsync(LocalAuditSession audit, TextWriter stderr)
    {
        await audit.FlushAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        await audit.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task ReportProblemsAsync(IReadOnlyList<string> problems, TextWriter stderr)
    {
        foreach (var problem in problems)
        {
            await stderr.WriteLineAsync(FormatProblem(problem)).ConfigureAwait(false);
        }
    }

    /// <summary>Synchronous because the problem callback is; stderr writes are short.</summary>
    private static void ReportProblem(string problem, TextWriter stderr) =>
        stderr.WriteLine(FormatProblem(problem));

    private static string FormatProblem(string problem) =>
        StderrLogger.Format(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = "audit_unavailable",
            ["detail"] = problem,
        });

    private static async Task<int> RunProxyAsync(
        string targetCommand, string[] targetArgs, HookConfig config, DetectorPreset preset,
        int maxScanBytes, TimeSpan placeholderIdleExpiry, TextWriter stderr, CancellationToken ct,
        IToolCallGuard? guard, IApprovalStore? approvalStore, TimeSpan? approvalWait,
        LocalAuditSession audit, Func<(ITransport Host, IClientTransport Target)>? transportFactory)
    {
        var (hostTransport, targetTransport) = transportFactory?.Invoke() ?? (
            // StdioServerTransport(string serverName, ILoggerFactory?) uses Console.In/Out internally.
            new StdioServerTransport(serverName: "sentinel-mcp", loggerFactory: NullLoggerFactory.Instance),
            McpProxy.CreateClientTransport(targetCommand, targetArgs));

        try
        {
            await McpProxy.RunAsync(
                hostTransport: hostTransport,
                targetTransport: targetTransport,
                config: config,
                preset: preset,
                maxScanBytes: maxScanBytes,
                stderr: stderr,
                ct: ct,
                guard: guard,
                approvalStore: approvalStore,
                approvalWait: approvalWait,
                auditStore: audit.Store,
                forwarders: audit.Forwarders,
                placeholderIdleExpiry: placeholderIdleExpiry).ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Clean shutdown via Ctrl+C — not an error.
            return 0;
        }
        catch (Exception ex) when (IsTargetFailure(ex))
        {
            await stderr.WriteLineAsync(
                $"sentinel-mcp: target process failed: {ex.Message}"
            ).ConfigureAwait(false);
            return 2;
        }
    }

    private static Dictionary<string, string?> ReadSentinelEnvironment()
        => Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .Where(e => e.Key is string k
                && (k.StartsWith("SENTINEL_HOOK_", StringComparison.Ordinal)
                 || k.StartsWith("SENTINEL_MCP_", StringComparison.Ordinal)))
            .ToDictionary(
                e => (string)e.Key,
                e => e.Value as string,
                StringComparer.Ordinal);

    /// <summary>
    /// Builds the <see cref="HookConfig"/> with CLI-flag-takes-precedence-over-env semantics.
    /// CLI flags (<c>--on-critical</c>/<c>--on-high</c>/<c>--on-medium</c>/<c>--on-low</c>)
    /// override the corresponding <c>SENTINEL_MCP_ON_*</c> env vars, which fall back to the
    /// existing <c>SENTINEL_HOOK_ON_*</c> env vars consumed by <see cref="HookConfig.FromEnvironment"/>.
    /// <c>SENTINEL_MCP_COMPLIANCE</c> and <c>SENTINEL_MCP_REDACT</c> likewise fall back to their
    /// <c>SENTINEL_HOOK_*</c> counterparts.
    /// </summary>
    internal static HookConfig ResolveHookConfig(string[] args, IReadOnlyDictionary<string, string?> envVars)
    {
        var envBaseline = HookConfig.FromEnvironment(envVars);
        return envBaseline with
        {
            OnCritical = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_CRITICAL", envBaseline.OnCritical),
            OnHigh = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_HIGH", envBaseline.OnHigh),
            OnMedium = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_MEDIUM", envBaseline.OnMedium),
            OnLow = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_LOW", envBaseline.OnLow),
            EnableComplianceDetectors = HookConfig.ParseSwitch(envVars, "SENTINEL_MCP_COMPLIANCE") ?? envBaseline.EnableComplianceDetectors,
            RedactToolResults = HookConfig.ParseSwitch(envVars, "SENTINEL_MCP_REDACT") ?? envBaseline.RedactToolResults,
        };
    }

    /// <summary>Reads <c>SENTINEL_MCP_DETECTORS</c>, falling back to <c>SENTINEL_HOOK_DETECTORS</c> when it is unset or
    /// empty. See <see cref="DetectorPresets.Parse"/>.</summary>
    internal static DetectorPreset ParsePreset(IReadOnlyDictionary<string, string?> env)
    {
        if (!env.TryGetValue("SENTINEL_MCP_DETECTORS", out var value) || string.IsNullOrEmpty(value))
            env.TryGetValue("SENTINEL_HOOK_DETECTORS", out value);
        return DetectorPresets.Parse(value);
    }

    /// <summary>Reads <c>SENTINEL_MCP_MAX_SCAN_BYTES</c>, the per-item UTF-8 byte cap shared by tool results, prompts and
    /// resource reads. A positive integer is taken; anything else keeps the 262144 byte default.</summary>
    internal static int ParseMaxScanBytes(IReadOnlyDictionary<string, string?> env)
    {
        if (env.TryGetValue("SENTINEL_MCP_MAX_SCAN_BYTES", out var value)
            && int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            && parsed > 0)
            return parsed;
        return 262144; // 256 KB default, shared by every interceptor
    }

    /// <summary>Reads <c>SENTINEL_MCP_REDACT_TTL_MIN</c>, how many minutes a placeholder the proxy minted stays
    /// restorable after its last use. A positive integer is taken; anything else keeps
    /// <see cref="Redaction.PlaceholderStore.DefaultIdleExpiry"/>.</summary>
    internal static TimeSpan ParseRedactionIdleExpiry(IReadOnlyDictionary<string, string?> env)
    {
        if (env.TryGetValue("SENTINEL_MCP_REDACT_TTL_MIN", out var value)
            && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var minutes)
            && minutes > 0)
            return TimeSpan.FromMinutes(minutes);
        return Redaction.PlaceholderStore.DefaultIdleExpiry;
    }

    private static bool IsTargetFailure(Exception ex) =>
        ex is System.ComponentModel.Win32Exception
           or System.IO.FileNotFoundException
           or System.IO.IOException;

    /// <summary>
    /// Loads <c>SENTINEL_APPROVAL_CONFIG</c> (if set), builds an <see cref="IToolCallGuard"/> +
    /// <see cref="IApprovalStore"/> via a small DI container, and resolves
    /// <c>SENTINEL_MCP_APPROVAL_WAIT_SEC</c>. Returns the <see cref="ServiceProvider"/> alongside
    /// so the caller can dispose it on shutdown (otherwise SQLite WAL/SHM aren't flushed). Returns
    /// <c>(null, null, null, null, false)</c> when no approval config is configured (the legacy
    /// no-authz path) and <c>configError=true</c> when the config is malformed or asks for a
    /// backend not bundled in this build. The returned store is wrapped so its approval decisions
    /// are written to <paramref name="auditStore"/> when one is given.
    /// </summary>
    /// <param name="stderr">Receives config load errors.</param>
    /// <param name="auditStore">The proxy's audit store; null keeps AddAISentinel's in-memory audit store.</param>
    /// <param name="forwarders">The proxy's audit forwarders, registered with <paramref name="auditStore"/>.</param>
    internal static async Task<(ServiceProvider? Provider, IToolCallGuard? Guard, IApprovalStore? Store, TimeSpan? Wait, bool ConfigError)> BuildAuthorizationStackAsync(
        TextWriter stderr, IAuditStore? auditStore = null, IReadOnlyList<IAuditForwarder>? forwarders = null)
    {
        var path = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");
        if (string.IsNullOrWhiteSpace(path)) return (null, null, null, null, false);

        ApprovalConfig approvalConfig;
        try
        {
            approvalConfig = ApprovalConfigLoader.Load(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or InvalidOperationException or JsonException)
        {
            await stderr.WriteLineAsync(
                $"sentinel-mcp: failed to load approval config from '{path}': {ex.Message}").ConfigureAwait(false);
            return (null, null, null, null, true);
        }

        // Backend stores must be registered BEFORE AddAISentinel: when bindings carry an
        // ApprovalSpec and no IApprovalStore is yet registered, AddAISentinel auto-registers
        // InMemoryApprovalStore — the Sqlite/EntraPim DI extensions throw on duplicate
        // registration, so they must be wired first.
        var services = new ServiceCollection();
        var backendKind = ApprovalBackendSelector.GetBackend(approvalConfig);
        switch (backendKind)
        {
            case ApprovalBackendKind.Sqlite:
                services.AddSentinelSqliteApprovalStore(o => o.DatabasePath = approvalConfig.DatabasePath!);
                break;
            case ApprovalBackendKind.EntraPim:
                services.AddSentinelEntraPimApprovalStore(o => o.TenantId = approvalConfig.TenantId!);
                break;
                // None / InMemory: AddAISentinel auto-registers InMemoryApprovalStore when bindings
                // carry an ApprovalSpec.
        }

        services.AddAISentinel(opts => ApprovalBackendSelector.Configure(opts, approvalConfig));

        // Last registration wins for IAuditStore, so these go after AddAISentinel's in-memory default.
        // Without them the approval decisions the stack observes would land in that throwaway store.
        if (auditStore is not null)
        {
            services.AddSingleton(auditStore);
            foreach (var forwarder in forwarders ?? [])
                services.AddSingleton(forwarder);
        }

        var provider = services.BuildServiceProvider();
        var guard = provider.GetService<IToolCallGuard>();
        var store = ApprovalStoreAuditing.Resolve(provider);

        TimeSpan? wait = null;
        var rawWait = Environment.GetEnvironmentVariable("SENTINEL_MCP_APPROVAL_WAIT_SEC");
        if (!string.IsNullOrWhiteSpace(rawWait)
            && int.TryParse(rawWait, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            && seconds > 0)
        {
            wait = TimeSpan.FromSeconds(seconds);
        }

        return (provider, guard, store, wait, false);
    }
}
