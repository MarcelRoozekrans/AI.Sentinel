namespace AI.Sentinel.Approvals.Configuration;

/// <summary>One entry under <c>semantic.tools</c>. There is no grant scope: a semantic grant always covers the approved call.</summary>
/// <param name="Role">Backend binding, such as the role an approver needs.</param>
/// <param name="GrantMinutes">Grant lifetime, or null for <c>defaultGrantMinutes</c>.</param>
/// <param name="RequireJustification">Whether a justification is required, or null for the default of true.</param>
/// <param name="Paths">Argument paths to score, or null to score the tool's default text.</param>
/// <param name="Threshold">Per-tool threshold in (0, 1], or null to use the block's.</param>
internal sealed record SemanticToolConfig(
    string Role,
    int? GrantMinutes,
    bool? RequireJustification,
    IReadOnlyList<string>? Paths,
    float? Threshold);
