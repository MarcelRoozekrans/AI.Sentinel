using AI.Sentinel.Detection;

namespace AI.Sentinel.ClaudeCode;

internal static class HookSeverityMapper
{
    /// <summary>
    /// The severity action as an outcome: Block is deny, Warn is guidance, Allow is defer. A policy or a profile may set the
    /// outcome per severity (<see cref="HookConfig.SeverityOutcomes"/>). Where the <c>SENTINEL_HOOK_ON_*</c> variable of the
    /// severity was set too, the stricter of the two applies; where it was not, only the policy counts, and the built-in
    /// default applies only when the policy sets nothing for the severity.
    /// </summary>
    public static DecisionOutcome MapOutcome(Severity severity, HookConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var variable = DecisionOutcomes.FromHook(severity switch
        {
            Severity.Critical => config.OnCritical,
            Severity.High => config.OnHigh,
            Severity.Medium => config.OnMedium,
            Severity.Low => config.OnLow,
            _ => HookDecision.Allow,
        });
        if (config.SeverityOutcomes is not { } set || !set.TryGet(severity, out var fromPolicy))
        {
            return variable;
        }

        return config.ExplicitSeverities.HasFlag(FlagOf(severity)) ? DecisionOutcomes.Strictest(variable, fromPolicy) : fromPolicy;
    }

    private static SeverityFlags FlagOf(Severity severity) => severity switch
    {
        Severity.Critical => SeverityFlags.Critical,
        Severity.High => SeverityFlags.High,
        Severity.Medium => SeverityFlags.Medium,
        Severity.Low => SeverityFlags.Low,
        _ => SeverityFlags.None,
    };

    /// <summary>The hook decision for <paramref name="severity"/>: <see cref="MapOutcome"/> carried back as a decision,
    /// which gives the configured action unchanged.</summary>
    public static HookDecision Map(Severity severity, HookConfig config) =>
        DecisionOutcomes.ToHook(MapOutcome(severity, config));
}
