namespace AI.Sentinel.Approvals.Conditions;

/// <summary>The outcome of evaluating an <see cref="ArgumentCondition"/>. Everything except
/// <see cref="DoesNotHold"/> counts as holding, so the approval gate fails closed.</summary>
internal enum ConditionResult
{
    /// <summary>The path resolved and its text matched the regex.</summary>
    Holds,

    /// <summary>The path did not resolve, or its text did not match.</summary>
    DoesNotHold,

    /// <summary>The regex exceeded its match timeout.</summary>
    TimedOut,

    /// <summary>The arguments on the path hold a string or property name that cannot be decoded.</summary>
    Unreadable,

    /// <summary>An object on the path has duplicate keys for the segment's name.</summary>
    AmbiguousKey,
}
