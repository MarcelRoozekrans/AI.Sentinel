using System.Globalization;
using System.Text.Json;
using AI.Sentinel;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Configuration;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Server;

namespace AI.Sentinel.Mcp.Cli;

internal static class ProxyCommand
{
    /// <summary>Parses <c>proxy --target &lt;cmd&gt; [&lt;target-args&gt;...]</c> and runs the proxy.</summary>
    public static async Task<int> RunAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr, CancellationToken ct)
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

        // Optional approval-config wiring. When SENTINEL_APPROVAL_CONFIG is set, build a guard +
        // approval store so the MCP proxy can gate tool calls behind PIM-style approvals. The
        // SENTINEL_MCP_APPROVAL_WAIT_SEC env var (positive integer) opts into wait-and-block; without
        // it the proxy fails fast with the receipt embedded in the JSON-RPC error. Provider owns
        // the SqliteApprovalStore connection / EntraPim Graph client and must be disposed on
        // shutdown so SQLite WAL/SHM are flushed cleanly.
        var (provider, guard, approvalStore, approvalWait, configError) = await BuildAuthorizationStackAsync(stderr).ConfigureAwait(false);
        if (configError) return 1;
        try
        {
            return await RunProxyAsync(
                targetCommand, targetArgs, config, preset, maxScanBytes,
                stderr, ct, guard, approvalStore, approvalWait).ConfigureAwait(false);
        }
        finally
        {
            if (provider is not null) await provider.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task<int> RunProxyAsync(
        string targetCommand, string[] targetArgs, HookConfig config, McpDetectorPreset preset,
        int maxScanBytes, TextWriter stderr, CancellationToken ct,
        IToolCallGuard? guard, IApprovalStore? approvalStore, TimeSpan? approvalWait)
    {
        var targetTransport = McpProxy.CreateClientTransport(targetCommand, targetArgs);

        // StdioServerTransport(string serverName, ILoggerFactory?) uses Console.In/Out internally.
        var hostTransport = new StdioServerTransport(
            serverName: "sentinel-mcp",
            loggerFactory: NullLoggerFactory.Instance);

        try
        {
            await McpProxy.RunAsync(
                hostTransport:   hostTransport,
                targetTransport: targetTransport,
                config:          config,
                preset:          preset,
                maxScanBytes:    maxScanBytes,
                stderr:          stderr,
                ct:              ct,
                guard:           guard,
                approvalStore:   approvalStore,
                approvalWait:    approvalWait).ConfigureAwait(false);
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
    /// </summary>
    private static HookConfig ResolveHookConfig(string[] args, IReadOnlyDictionary<string, string?> envVars)
    {
        var envBaseline = HookConfig.FromEnvironment(envVars);
        return envBaseline with
        {
            OnCritical = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_CRITICAL", envBaseline.OnCritical),
            OnHigh     = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_HIGH",     envBaseline.OnHigh),
            OnMedium   = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_MEDIUM",   envBaseline.OnMedium),
            OnLow      = SeverityFlagParser.Parse(args, "SENTINEL_MCP_ON_LOW",      envBaseline.OnLow),
        };
    }

    private static McpDetectorPreset ParsePreset(IReadOnlyDictionary<string, string?> env)
    {
        if (!env.TryGetValue("SENTINEL_MCP_DETECTORS", out var value) || string.IsNullOrEmpty(value))
            return McpDetectorPreset.Security;
        return value.Equals("all", StringComparison.OrdinalIgnoreCase)
            ? McpDetectorPreset.All
            : McpDetectorPreset.Security;
    }

    private static int ParseMaxScanBytes(IReadOnlyDictionary<string, string?> env)
    {
        if (env.TryGetValue("SENTINEL_MCP_MAX_SCAN_BYTES", out var value)
            && int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            && parsed > 0)
            return parsed;
        return 262144; // 256 KB default
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
    /// backend not bundled in this build.
    /// </summary>
    internal static async Task<(ServiceProvider? Provider, IToolCallGuard? Guard, IApprovalStore? Store, TimeSpan? Wait, bool ConfigError)> BuildAuthorizationStackAsync(TextWriter stderr)
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

        var provider = services.BuildServiceProvider();
        var guard = provider.GetService<IToolCallGuard>();
        var store = provider.GetService<IApprovalStore>();

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
