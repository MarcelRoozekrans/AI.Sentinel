using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>What a hook sends to open an approval request. The server takes the requester from the validated token, never from
/// this body. <see cref="Args"/> is the tool input after AI.Sentinel's redaction (ADR-027), never the raw input.</summary>
internal sealed record ApprovalRequestWire
{
    /// <summary>The normalised name of the git remote of the working directory; empty outside git. It decides which node's team lead may
    /// decide the request.</summary>
    public string Repository { get; init; } = "";

    /// <summary>The name of the approval rule; with the requester it identifies the request.</summary>
    public string Policy { get; init; } = "";

    /// <summary>The tool the call is for.</summary>
    public string Tool { get; init; } = "";

    /// <summary>The redacted tool input, so the approver sees what they approve.</summary>
    public JsonElement? Args { get; init; }

    public string? Justification { get; init; }

    /// <summary>Why the call needs approval, when something other than a configured rule decided it.</summary>
    public string? Reason { get; init; }

    /// <summary>How long a grant lasts once approved.</summary>
    public int GrantSeconds { get; init; }
}
