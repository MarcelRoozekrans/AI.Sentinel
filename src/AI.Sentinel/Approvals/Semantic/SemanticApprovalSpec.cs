using AI.Sentinel.Approvals.Conditions;

namespace AI.Sentinel.Approvals.Semantic;

/// <summary>
/// Configuration for a semantic approval binding: a tool call whose text is close in meaning to a
/// configured example needs approval. Grants always cover only the approved call.
/// </summary>
public sealed class SemanticApprovalSpec
{
    /// <summary>Backend-specific identifier (for example the role name a role-based store approves).
    /// Required when the binding is registered.</summary>
    public string BackendBinding { get; set; } = string.Empty;

    /// <summary>How long an approved grant remains active before re-approval is needed.</summary>
    public TimeSpan GrantDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Whether a justification string must be provided at request time.</summary>
    public bool RequireJustification { get; set; } = true;

    /// <summary>Maximum time a host that block-and-waits will tolerate before timing out.</summary>
    public TimeSpan WaitTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Similarity needed for a match, in the range above 0 up to and including 1.
    /// Null uses the global threshold.</summary>
    public float? Threshold { get; set; }

    /// <summary>The parsed paths set with <see cref="Paths"/>; null when the whole arguments JSON is scored.</summary>
    internal IReadOnlyList<ArgumentPath>? ParsedPaths { get; private set; }

    /// <summary>Limits scoring to the text found at the given paths into the tool arguments.</summary>
    /// <param name="jsonPaths">One or more paths, for example <c>$.command</c>.</param>
    /// <returns>The same <see cref="SemanticApprovalSpec"/> for fluent chaining.</returns>
    /// <exception cref="ArgumentException">No path is given, or a path is invalid.</exception>
    public SemanticApprovalSpec Paths(params string[] jsonPaths)
    {
        ArgumentNullException.ThrowIfNull(jsonPaths);
        if (jsonPaths.Length == 0)
            throw new ArgumentException("At least one path is required.", nameof(jsonPaths));
        ParsedPaths = jsonPaths.Select(ArgumentPath.Parse).ToArray();
        return this;
    }
}
