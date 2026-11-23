namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>The input a policy is evaluated against (ADR-235), package <c>sentinel</c>.</summary>
/// <param name="Kind">Wire name of the <see cref="ToolKind"/>.</param>
/// <param name="Cli">Wire name of the CLI, see <see cref="PolicyClis"/>.</param>
/// <param name="Tool">The CLI's own tool name.</param>
/// <param name="Details">The details of the kind.</param>
/// <param name="Findings">Detector findings for this call.</param>
/// <param name="Repository">The repository. Empty until the issue that resolves it fills it.</param>
/// <param name="Node">The owning node. Empty until the issue that resolves it fills it.</param>
/// <param name="Session">The session id.</param>
internal sealed record PolicyInput(
    string Kind,
    string Cli,
    string Tool,
    PolicyDetails Details,
    IReadOnlyList<PolicyFinding> Findings,
    string Repository,
    string Node,
    string Session);
