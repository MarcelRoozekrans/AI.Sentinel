namespace AI.Sentinel.ClaudeCode;

internal static class DecisionOutcomes
{
    /// <summary>The stricter of two outcomes.</summary>
    public static DecisionOutcome Strictest(DecisionOutcome a, DecisionOutcome b) => a <= b ? a : b;

    /// <summary>Today's severity action as an outcome: Block is deny, Warn is guidance, Allow is defer.</summary>
    public static DecisionOutcome FromHook(HookDecision decision) => decision switch
    {
        HookDecision.Block => DecisionOutcome.Deny,
        HookDecision.Warn => DecisionOutcome.Guidance,
        _ => DecisionOutcome.Defer,
    };

    /// <summary>The hook decision an outcome is carried as: deny is Block, ask and guidance are Warn, allow and defer are
    /// Allow. An ask that the CLI cannot express is turned into a deny before this is used.</summary>
    public static HookDecision ToHook(DecisionOutcome outcome) => outcome switch
    {
        DecisionOutcome.Deny => HookDecision.Block,
        DecisionOutcome.Ask or DecisionOutcome.Guidance => HookDecision.Warn,
        _ => HookDecision.Allow,
    };

    /// <summary>Lower-case name used in the audit and in documentation.</summary>
    public static string Name(DecisionOutcome outcome) => outcome switch
    {
        DecisionOutcome.Deny => "deny",
        DecisionOutcome.Ask => "ask",
        DecisionOutcome.Guidance => "guidance",
        DecisionOutcome.Allow => "allow",
        _ => "defer",
    };
}
