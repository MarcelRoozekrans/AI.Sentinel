using AI.Sentinel.Authorization;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// Configuration for <see cref="HookAdapter"/>: severity-to-decision mapping, verbosity, and
/// the optional <see cref="CallerContextProvider"/> used by the <see cref="IToolCallGuard"/>
/// integration on <see cref="HookEvent.PreToolUse"/>.
/// </summary>
public sealed record HookConfig
{
    /// <summary>Decision to return when the detection pipeline reports <c>Critical</c> severity.</summary>
    public HookDecision OnCritical { get; init; } = HookDecision.Block;

    /// <summary>Decision to return when the detection pipeline reports <c>High</c> severity.</summary>
    public HookDecision OnHigh { get; init; } = HookDecision.Block;

    /// <summary>Decision to return when the detection pipeline reports <c>Medium</c> severity.</summary>
    public HookDecision OnMedium { get; init; } = HookDecision.Warn;

    /// <summary>Decision to return when the detection pipeline reports <c>Low</c> severity.</summary>
    public HookDecision OnLow { get; init; } = HookDecision.Allow;

    /// <summary>When true, the hook CLI emits diagnostic output.</summary>
    public bool Verbose { get; init; }

    /// <summary>When true, suppresses the startup warning that semantic detection is inert.
    /// Set it only after accepting that SEC-01 and SEC-05 will not fire.</summary>
    public bool SuppressSemanticWarning { get; init; }

    /// <summary>When true, the Art. 5 compliance detectors CMP-01 to CMP-04 run. They are off by default; when on,
    /// a finding warns instead of following <see cref="OnHigh"/>. Set by <c>SENTINEL_HOOK_COMPLIANCE=on</c>.</summary>
    public bool EnableComplianceDetectors { get; init; }

    /// <summary>When true, tool results, prompts and resources on their way to the model get placeholders instead of
    /// the sensitive values they hold, where the host lets Sentinel rewrite them, and PreToolUse denies a write or shell
    /// tool whose input holds a redaction placeholder. When false, a finding falls back to its severity action and is
    /// audited with <c>; not redacted</c>.
    /// <para>
    /// False by default, which keeps the 3.0 behaviour for a caller that builds its own config: a secret in a tool
    /// result blocks. A caller that sets it must apply <see cref="HookOutput.UpdatedToolOutput"/> on
    /// <see cref="HookEvent.PostToolUse"/>, because the decision is then Allow and only the replaced output keeps the
    /// value from the model. <see cref="FromEnvironment"/>, which the hook CLIs and the MCP proxy use, turns it on unless
    /// <c>SENTINEL_HOOK_REDACT</c> is <c>off</c>, <c>0</c>, <c>false</c> or <c>no</c>.
    /// </para></summary>
    public bool RedactToolResults { get; init; }

    /// <summary>
    /// Resolves the caller identity from the hook input. When <c>null</c> (the default),
    /// <see cref="AnonymousSecurityContext.Instance"/> is used for authorization checks.
    /// </summary>
    public Func<HookInput, ISecurityContext>? CallerContextProvider { get; init; }

    public static HookConfig FromEnvironment(IReadOnlyDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        return new HookConfig
        {
            OnCritical = ParseDecision(env, "SENTINEL_HOOK_ON_CRITICAL", HookDecision.Block),
            OnHigh = ParseDecision(env, "SENTINEL_HOOK_ON_HIGH", HookDecision.Block),
            OnMedium = ParseDecision(env, "SENTINEL_HOOK_ON_MEDIUM", HookDecision.Warn),
            OnLow = ParseDecision(env, "SENTINEL_HOOK_ON_LOW", HookDecision.Allow),
            Verbose = ParseVerbose(env, "SENTINEL_HOOK_VERBOSE"),
            SuppressSemanticWarning = ParseVerbose(env, "SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING"),
            EnableComplianceDetectors = ParseSwitch(env, "SENTINEL_HOOK_COMPLIANCE") ?? false,
            RedactToolResults = ParseSwitch(env, "SENTINEL_HOOK_REDACT") ?? true,
        };
    }

    private static HookDecision ParseDecision(IReadOnlyDictionary<string, string?> env, string key, HookDecision fallback)
        => env.TryGetValue(key, out var v) && Enum.TryParse<HookDecision>(v, ignoreCase: true, out var d) ? d : fallback;

    /// <summary>Reads an on/off switch: <c>on</c>, <c>1</c>, <c>true</c> or <c>yes</c> is on, <c>off</c>, <c>0</c>,
    /// <c>false</c> or <c>no</c> is off, and anything else, or nothing, is <see langword="null"/>, so the caller applies
    /// its default with <c>??</c>. Shared by the Copilot hook config and the MCP proxy.</summary>
    internal static bool? ParseSwitch(IReadOnlyDictionary<string, string?> env, string key)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (!env.TryGetValue(key, out var value) || string.IsNullOrEmpty(value)) return null;
        if (value is "1" || value.Equals("on", StringComparison.OrdinalIgnoreCase)
            || value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase))
            return true;
        if (value is "0" || value.Equals("off", StringComparison.OrdinalIgnoreCase)
            || value.Equals("false", StringComparison.OrdinalIgnoreCase) || value.Equals("no", StringComparison.OrdinalIgnoreCase))
            return false;
        return null;
    }

    /// <summary>Reads a scan budget in UTF-8 bytes, such as <c>SENTINEL_HOOK_MAX_SCAN_BYTES</c>: a positive integer is
    /// taken, anything else, or nothing, keeps the <see cref="SentinelOptions.MaxScanBytes"/> default of 262144. Shared by
    /// the Claude Code and Copilot hook CLIs and the MCP proxy.</summary>
    internal static int ParseMaxScanBytes(IReadOnlyDictionary<string, string?> env, string key)
    {
        ArgumentNullException.ThrowIfNull(env);
        return env.TryGetValue(key, out var value)
            && int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            && parsed > 0
                ? parsed
                : SentinelOptions.DefaultMaxScanBytes;
    }

    private static bool ParseVerbose(IReadOnlyDictionary<string, string?> env, string key)
    {
        if (!env.TryGetValue(key, out var v) || string.IsNullOrEmpty(v)) return false;
        return string.Equals(v, "1", StringComparison.Ordinal)
            || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(v, "yes", StringComparison.OrdinalIgnoreCase);
    }
}
