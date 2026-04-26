using System.Globalization;
using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Mcp.Cli;

/// <summary>
/// Resolves a severity decision with CLI-flag-takes-precedence-over-env semantics.
/// Precedence: CLI flag > env var > fallback. Garbage CLI values log to stderr and
/// fall through to the env var (then fallback) — never crash the proxy.
/// </summary>
public static class SeverityFlagParser
{
    /// <summary>
    /// Parses a severity decision from CLI args, falling back to the named env var,
    /// and finally the supplied <paramref name="fallback"/>. The flag name is derived
    /// from the env var by stripping the <c>SENTINEL_MCP_</c> (or <c>SENTINEL_HOOK_</c>)
    /// prefix and lower-kebab-casing the remainder
    /// (e.g. <c>SENTINEL_MCP_ON_CRITICAL</c> -&gt; <c>--on-critical</c>).
    /// </summary>
    public static HookDecision Parse(string[] args, string envVar, HookDecision fallback)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentException.ThrowIfNullOrEmpty(envVar);

        var flagName = DeriveFlagName(envVar);

        // CLI flag wins if present and parseable.
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (!string.Equals(args[i], flagName, StringComparison.Ordinal))
                continue;

            var raw = args[i + 1];
            if (Enum.TryParse<HookDecision>(raw, ignoreCase: true, out var v))
                return v;

            // Garbage CLI value — log and fall through to env/fallback.
            Console.Error.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"event=cli_severity_parse flag={flagName} value={raw} error=invalid_value"));
            break;
        }

        // Env var (case-insensitive enum parse).
        var envValue = Environment.GetEnvironmentVariable(envVar);
        if (!string.IsNullOrEmpty(envValue)
            && Enum.TryParse<HookDecision>(envValue, ignoreCase: true, out var ev))
        {
            return ev;
        }

        return fallback;
    }

    private static string DeriveFlagName(string envVar)
    {
        // Strip known prefixes; treat the remainder as the flag body.
        var body = envVar;
        if (body.StartsWith("SENTINEL_MCP_", StringComparison.Ordinal))
            body = body["SENTINEL_MCP_".Length..];
        else if (body.StartsWith("SENTINEL_HOOK_", StringComparison.Ordinal))
            body = body["SENTINEL_HOOK_".Length..];

        return "--" + body.Replace('_', '-').ToLowerInvariant();
    }
}
