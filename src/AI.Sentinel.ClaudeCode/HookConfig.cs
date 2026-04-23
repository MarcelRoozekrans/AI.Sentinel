namespace AI.Sentinel.ClaudeCode;

public sealed record HookConfig(
    HookDecision OnCritical = HookDecision.Block,
    HookDecision OnHigh = HookDecision.Block,
    HookDecision OnMedium = HookDecision.Warn,
    HookDecision OnLow = HookDecision.Allow,
    bool Verbose = false)
{
    public static HookConfig FromEnvironment(IReadOnlyDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        return new HookConfig(
            OnCritical: ParseDecision(env, "SENTINEL_HOOK_ON_CRITICAL", HookDecision.Block),
            OnHigh:     ParseDecision(env, "SENTINEL_HOOK_ON_HIGH",     HookDecision.Block),
            OnMedium:   ParseDecision(env, "SENTINEL_HOOK_ON_MEDIUM",   HookDecision.Warn),
            OnLow:      ParseDecision(env, "SENTINEL_HOOK_ON_LOW",      HookDecision.Allow),
            Verbose:    ParseVerbose(env, "SENTINEL_HOOK_VERBOSE"));
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
