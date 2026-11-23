using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>One request in the list an approver reads.</summary>
internal sealed record ApprovalListItemWire
{
    public string Id { get; init; } = "";
    public string Requester { get; init; } = "";
    public string Repository { get; init; } = "";
    public string Policy { get; init; } = "";
    public string Tool { get; init; } = "";
    public JsonElement? Args { get; init; }
    public string? Justification { get; init; }
    public string? RequestReason { get; init; }
    public DateTimeOffset RequestedAt { get; init; }
    public string State { get; init; } = "";
    public DateTimeOffset? DecidedAt { get; init; }
    public string? Decider { get; init; }
    public string? Reason { get; init; }
}
