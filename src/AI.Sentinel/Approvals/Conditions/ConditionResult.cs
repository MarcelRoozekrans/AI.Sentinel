namespace AI.Sentinel.Approvals.Conditions;

/// <summary>The outcome of evaluating an <see cref="ArgumentCondition"/>.</summary>
internal enum ConditionResult
{
    /// <summary>The path resolved and its text matched the regex.</summary>
    Holds,

    /// <summary>The path did not resolve, or its text did not match.</summary>
    DoesNotHold,

    /// <summary>The regex exceeded its match timeout.</summary>
    TimedOut,
}
