using AI.Sentinel.Approvals;

namespace AI.Sentinel.Approvals.Configuration;

/// <summary>One approval rule for a tool inside <see cref="ApprovalConfig.Tools"/>. A tool maps to
/// an ordered list of these; the first whose <see cref="When"/> conditions hold applies.</summary>
/// <param name="Role">Backend role the approval is bound to.</param>
/// <param name="GrantMinutes">Grant duration override, or <see langword="null"/> for the config default.</param>
/// <param name="RequireJustification">Justification override, or <see langword="null"/> for the default.</param>
/// <param name="GrantScope">What an approval grant covers.</param>
internal sealed record ApprovalToolConfig(
    string Role,
    int? GrantMinutes,
    bool? RequireJustification,
    ApprovalGrantScope GrantScope = ApprovalGrantScope.Rule)
{
    /// <summary>JSON path and regex pairs in file order; empty when absent.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> When { get; init; } =
        Array.Empty<KeyValuePair<string, string>>();
}
