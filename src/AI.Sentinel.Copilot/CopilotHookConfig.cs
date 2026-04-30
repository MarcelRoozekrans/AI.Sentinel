using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Copilot;

/// <summary>
/// Configuration for <see cref="CopilotHookAdapter"/>: severity-to-decision mapping, verbosity, and
/// the optional <see cref="CallerContextProvider"/> used by the <see cref="IToolCallGuard"/>
/// integration on <see cref="CopilotHookEvent.PreToolUse"/>.
/// </summary>
/// <param name="OnCritical">Decision to return when the detection pipeline reports <c>Critical</c> severity.</param>
/// <param name="OnHigh">Decision to return when the detection pipeline reports <c>High</c> severity.</param>
/// <param name="OnMedium">Decision to return when the detection pipeline reports <c>Medium</c> severity.</param>
/// <param name="OnLow">Decision to return when the detection pipeline reports <c>Low</c> severity.</param>
/// <param name="Verbose">When true, the hook CLI emits diagnostic output.</param>
public sealed record CopilotHookConfig(
    HookDecision OnCritical = HookDecision.Block,
    HookDecision OnHigh = HookDecision.Block,
    HookDecision OnMedium = HookDecision.Warn,
    HookDecision OnLow = HookDecision.Allow,
    bool Verbose = false)
{
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
        return new CopilotHookConfig(
            OnCritical: ParseDecision(env, "SENTINEL_HOOK_ON_CRITICAL", HookDecision.Block),
            OnHigh:     ParseDecision(env, "SENTINEL_HOOK_ON_HIGH",     HookDecision.Block),
            OnMedium:   ParseDecision(env, "SENTINEL_HOOK_ON_MEDIUM",   HookDecision.Warn),
            OnLow:      ParseDecision(env, "SENTINEL_HOOK_ON_LOW",      HookDecision.Allow),
            Verbose:    ParseVerbose(env, "SENTINEL_HOOK_VERBOSE"));
    }

    /// <summary>
    /// Projects this Copilot config onto the shared <see cref="HookConfig"/> used by
    /// <see cref="HookPipelineRunner"/> (severity mapping + verbosity only — the
    /// <see cref="CallerContextProvider"/> stays Copilot-side because it binds to
    /// <see cref="CopilotHookInput"/>).
    /// </summary>
    internal HookConfig ToSharedConfig()
        => new(OnCritical, OnHigh, OnMedium, OnLow, Verbose);

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
