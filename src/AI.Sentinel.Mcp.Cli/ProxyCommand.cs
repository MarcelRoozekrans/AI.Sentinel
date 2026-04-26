using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp;
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
        var config = HookConfig.FromEnvironment(envVars);
        var preset = ParsePreset(envVars);
        var maxScanBytes = ParseMaxScanBytes(envVars);

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
                ct:              ct).ConfigureAwait(false);
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
}
