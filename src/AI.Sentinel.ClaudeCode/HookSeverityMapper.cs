using AI.Sentinel.Detection;

namespace AI.Sentinel.ClaudeCode;

internal static class HookSeverityMapper
{
    /// <summary>The severity action as an outcome: Block is deny, Warn is guidance, Allow is defer. The
    /// <c>SENTINEL_HOOK_ON_*</c> values keep their names and their effect.</summary>
    public static DecisionOutcome MapOutcome(Severity severity, HookConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return DecisionOutcomes.FromHook(severity switch
        {
            Severity.Critical => config.OnCritical,
            Severity.High => config.OnHigh,
            Severity.Medium => config.OnMedium,
            Severity.Low => config.OnLow,
            _ => HookDecision.Allow,
        });
    }

    /// <summary>The hook decision for <paramref name="severity"/>: <see cref="MapOutcome"/> carried back as a decision,
    /// which gives the configured action unchanged.</summary>
    public static HookDecision Map(Severity severity, HookConfig config) =>
        DecisionOutcomes.ToHook(MapOutcome(severity, config));
}
