using System.Text.Json;

namespace AI.Sentinel.Approvals;

/// <summary>A pending approval request as exposed by <see cref="IApprovalAdmin.ListPendingAsync"/>.</summary>
public sealed record PendingRequest(
    string RequestId,
    string CallerId,
    string PolicyName,
    string ToolName,
    JsonElement Args,
    DateTimeOffset RequestedAt,
    string? Justification)
{
    /// <summary>Why the call needs approval, fixed when the request was created, or <see langword="null"/> for a rule-based request.</summary>
    public string? Reason { get; init; }
}
