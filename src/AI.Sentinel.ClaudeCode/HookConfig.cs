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
        };
    }

    private static HookDecision ParseDecision(IReadOnlyDictionary<string, string?> env, string key, HookDecision fallback)
        => env.TryGetValue(key, out var v) && Enum.TryParse<HookDecision>(v, ignoreCase: true, out var d) ? d : fallback;

    private static bool ParseVerbose(IReadOnlyDictionary<string, string?> env, string key)
    {
        if (!env.TryGetValue(key, out var v) || string.IsNullOrEmpty(v)) return false;
        return string.Equals(v, "1", StringComparison.Ordinal)
            || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(v, "yes", StringComparison.OrdinalIgnoreCase);
    }
}
