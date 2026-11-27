using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>The state of one request, as the server answers a create or a read.</summary>
internal sealed record ApprovalStateWire
{
    public string Id { get; init; } = "";

    /// <summary>One of <see cref="ApprovalWireStates"/>.</summary>
    public string State { get; init; } = "";

    public DateTimeOffset RequestedAt { get; init; }

    /// <summary>For an active grant: when it ends.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>When the request was approved or denied.</summary>
    public DateTimeOffset? DecidedAt { get; init; }

    /// <summary>For a denied request: why, as the denier gave it, or <c>expired</c> for a grant that ran out.</summary>
    public string? Reason { get; init; }

    /// <summary>Why the call needs approval, fixed when the request was opened.</summary>
    public string? RequestReason { get; init; }

    /// <summary>Where the request is read, and decided by an approver, over the HTTP API.</summary>
    public string ApprovalUrl { get; init; } = "";

    /// <summary>True only on the answer to the create that opened the request.</summary>
    public bool IsNew { get; init; }
}
