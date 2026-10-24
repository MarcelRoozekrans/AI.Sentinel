namespace AI.Sentinel.Approvals.Conditions;

/// <summary>The outcome of resolving an <see cref="ArgumentPath"/> against tool arguments.</summary>
internal enum ArgumentPathResult
{
    /// <summary>The path resolved to a value with match text.</summary>
    Resolved,

    /// <summary>The path does not exist, the value is JSON null, or the arguments are not an object or array.</summary>
    NotFound,

    /// <summary>A property name or string on the way, or the value itself, holds an escape that does not
    /// decode to valid UTF-16, such as a lone surrogate.</summary>
    Unreadable,

    /// <summary>An object on the path has more than one property with the segment's name, so parsers
    /// that keep the first and parsers that keep the last would see different values.</summary>
    DuplicateKey,
}
