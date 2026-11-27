namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>How a call to the approval server ended.</summary>
internal enum ApprovalChannelStatus
{
    /// <summary>The server answered with a state.</summary>
    Ok,

    /// <summary>No answer: the server or the resident process cannot be reached, or answered something unusable. The call is denied.</summary>
    Unreachable,

    /// <summary>The developer is not signed in, or the server no longer accepts the token.</summary>
    SignInNeeded,

    /// <summary>The server answered that this developer may not do it.</summary>
    Refused,

    /// <summary>The server knows no such request.</summary>
    NotFound,

    /// <summary>There is nothing to ask: no resident process, or no server configured.</summary>
    Off,
}
