namespace AI.Sentinel.Approvals;

/// <summary>
/// How widely an approved grant applies to later calls that match the same approval rule.
/// </summary>
public enum ApprovalGrantScope
{
    /// <summary>A grant covers every call that matches the rule, whatever its arguments.</summary>
    Rule,

    /// <summary>A grant covers only calls with exactly the arguments that were approved.</summary>
    Call,
}
