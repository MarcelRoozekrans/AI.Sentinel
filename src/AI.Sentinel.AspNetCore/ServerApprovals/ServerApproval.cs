using System.Text.Json;

namespace AI.Sentinel.AspNetCore.ServerApprovals;

/// <summary>A snapshot of one approval request. Approval requests are their own dataset (#662): the tool input in it is the redacted one
/// the hook sent, so the approver sees what they approve, and the whole record is deleted
/// <see cref="ServerApprovalStore.Retention"/> after it is decided.</summary>
internal sealed record ServerApproval(
    string Id,
    string Requester,
    string Repository,
    string Policy,
    string Tool,
    JsonElement? Args,
    string? Justification,
    string? RequestReason,
    DateTimeOffset RequestedAt,
    TimeSpan GrantDuration,
    ServerApprovalStatus Status,
    DateTimeOffset? DecidedAt,
    string? Decider,
    string? Note)
{
    /// <summary>For an approved request: when the grant ends.</summary>
    public DateTimeOffset? ExpiresAt => Status == ServerApprovalStatus.Approved && DecidedAt is { } at ? at + GrantDuration : null;
}
