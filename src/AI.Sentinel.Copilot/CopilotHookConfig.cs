using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Copilot;

/// <summary>
/// Configuration for <see cref="CopilotHookAdapter"/>: severity-to-decision mapping, verbosity, and
/// the optional <see cref="CallerContextProvider"/> used by the <see cref="IToolCallGuard"/>
/// integration on <see cref="CopilotHookEvent.PreToolUse"/>.
/// </summary>
public sealed record CopilotHookConfig
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

    /// <summary>When true, the default, PreToolUse denies a write or shell tool whose input holds a redaction
    /// placeholder, and tool results are redacted where the host lets Sentinel rewrite them. Set by
    /// <c>SENTINEL_HOOK_REDACT</c>: <c>off</c>, <c>0</c>, <c>false</c> or <c>no</c> turn it off.</summary>
    public bool RedactToolResults { get; init; } = true;

    /// <summary>
    /// Resolves the caller identity from the hook input. When <c>null</c> (the default),
    /// <see cref="AnonymousSecurityContext.Instance"/> is used for authorization checks.
    /// </summary>
    public Func<CopilotHookInput, ISecurityContext>? CallerContextProvider { get; init; }

    /// <summary>
    /// Builds a <see cref="CopilotHookConfig"/> from <c>SENTINEL_HOOK_*</c> environment variables.
    /// </summary>
    public static CopilotHookConfig FromEnvironment(IReadOnlyDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        return new CopilotHookConfig
        {
            OnCritical = ParseDecision(env, "SENTINEL_HOOK_ON_CRITICAL", HookDecision.Block),
            OnHigh = ParseDecision(env, "SENTINEL_HOOK_ON_HIGH", HookDecision.Block),
            OnMedium = ParseDecision(env, "SENTINEL_HOOK_ON_MEDIUM", HookDecision.Warn),
            OnLow = ParseDecision(env, "SENTINEL_HOOK_ON_LOW", HookDecision.Allow),
            Verbose = ParseVerbose(env, "SENTINEL_HOOK_VERBOSE"),
            SuppressSemanticWarning = ParseVerbose(env, "SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING"),
            EnableComplianceDetectors = ParseSwitch(env, "SENTINEL_HOOK_COMPLIANCE"),
            RedactToolResults = HookConfig.ParseOnByDefault(env, "SENTINEL_HOOK_REDACT"),
        };
    }

    /// <summary>
    /// Projects this Copilot config onto the shared <see cref="HookConfig"/> used by
    /// <see cref="HookPipelineRunner"/> (severity mapping + verbosity only — the
    /// <see cref="CallerContextProvider"/> stays Copilot-side because it binds to
    /// <see cref="CopilotHookInput"/>).
    /// </summary>
    internal HookConfig ToSharedConfig()
        => new()
        {
            OnCritical = OnCritical,
            OnHigh = OnHigh,
            OnMedium = OnMedium,
            OnLow = OnLow,
            Verbose = Verbose,
            EnableComplianceDetectors = EnableComplianceDetectors,
            RedactToolResults = RedactToolResults,
        };

    private static HookDecision ParseDecision(IReadOnlyDictionary<string, string?> env, string key, HookDecision fallback)
        => env.TryGetValue(key, out var v) && Enum.TryParse<HookDecision>(v, ignoreCase: true, out var d) ? d : fallback;

    /// <summary>Reads an on/off switch: <c>on</c>, <c>1</c>, <c>true</c> or <c>yes</c> turn it on; anything else leaves it off.</summary>
    private static bool ParseSwitch(IReadOnlyDictionary<string, string?> env, string key)
    {
        if (!env.TryGetValue(key, out var v) || string.IsNullOrEmpty(v)) return false;
        return string.Equals(v, "on", StringComparison.OrdinalIgnoreCase) || ParseVerbose(env, key);
    }

    private static bool ParseVerbose(IReadOnlyDictionary<string, string?> env, string key)
    {
        if (!env.TryGetValue(key, out var v) || string.IsNullOrEmpty(v)) return false;
        return string.Equals(v, "1", StringComparison.Ordinal)
            || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(v, "yes", StringComparison.OrdinalIgnoreCase);
    }
}
