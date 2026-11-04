namespace AI.Sentinel.Approvals.Semantic;

/// <summary>The text a semantic approval scores could not be read from the call's arguments, so the call cannot
/// be scored and needs approval (fail closed).</summary>
internal sealed class SemanticTextException(string kind)
    : Exception($"The tool call's arguments cannot be scored: {kind}.")
{
    /// <summary>A string or property name holds an escape that does not decode to valid UTF-16, such as a lone surrogate.</summary>
    public const string UnreadableArguments = "unreadable arguments";

    /// <summary>An object on a selected path has the segment's name more than once, so parsers disagree on the value.</summary>
    public const string DuplicateKey = "duplicate key";

    /// <summary>The failure kind the <c>Semantic check failed</c> reason names.</summary>
    public string Kind { get; } = kind;
}
