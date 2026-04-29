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
    string? Justification);
