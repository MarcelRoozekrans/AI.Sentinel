using System.Text.Json;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Per-request context surfaced to the approver: the tool being invoked, its arguments,
/// and an optional justification string sourced from the agent's reasoning context.
/// </summary>
public sealed record ApprovalContext(
    string ToolName,
    JsonElement Args,
    string? Justification);
