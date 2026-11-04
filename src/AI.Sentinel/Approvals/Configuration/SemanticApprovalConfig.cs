namespace AI.Sentinel.Approvals.Configuration;

/// <summary>The <c>semantic</c> block of the approval config file: tool calls whose text is close in meaning to an example need approval.</summary>
/// <param name="Threshold">Block-wide similarity threshold in (0, 1], or null for the built-in value.</param>
/// <param name="Examples">Examples added to the built-in set, or the only examples when <paramref name="ReplaceExamples"/> is true.</param>
/// <param name="ReplaceExamples">Whether <paramref name="Examples"/> replaces the built-in set.</param>
/// <param name="Tools">The covered tools in file order: tool pattern to its entry.</param>
internal sealed record SemanticApprovalConfig(
    float? Threshold,
    IReadOnlyList<string> Examples,
    bool ReplaceExamples,
    IReadOnlyList<KeyValuePair<string, SemanticToolConfig>> Tools);
