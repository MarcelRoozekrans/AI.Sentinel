using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>The body of an approve or a deny; both fields are optional.</summary>
internal sealed record ApprovalDecisionWire
{
    /// <summary>A note an approver adds to an approval.</summary>
    public string? Note { get; init; }

    /// <summary>Why a request is denied; the requester's hook shows it.</summary>
    public string? Reason { get; init; }
}
