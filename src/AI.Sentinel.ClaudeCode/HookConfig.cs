namespace AI.Sentinel.ClaudeCode;

public sealed record HookConfig(
    HookDecision OnCritical = HookDecision.Block,
    HookDecision OnHigh = HookDecision.Block,
    HookDecision OnMedium = HookDecision.Warn,
    HookDecision OnLow = HookDecision.Allow)
{
    public static HookConfig FromEnvironment(IReadOnlyDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        return new HookConfig(
            OnCritical: Parse(env, "SENTINEL_HOOK_ON_CRITICAL", HookDecision.Block),
            OnHigh:     Parse(env, "SENTINEL_HOOK_ON_HIGH",     HookDecision.Block),
            OnMedium:   Parse(env, "SENTINEL_HOOK_ON_MEDIUM",   HookDecision.Warn),
            OnLow:      Parse(env, "SENTINEL_HOOK_ON_LOW",      HookDecision.Allow));
    }

    private static HookDecision Parse(IReadOnlyDictionary<string, string?> env, string key, HookDecision fallback)
        => env.TryGetValue(key, out var v) && Enum.TryParse<HookDecision>(v, ignoreCase: true, out var d) ? d : fallback;
}
