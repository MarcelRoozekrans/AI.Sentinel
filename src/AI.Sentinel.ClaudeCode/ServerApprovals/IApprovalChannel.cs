namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>The way the http approval backend reaches the server: through the resident process on a PC, directly in tests and in the
/// resident process itself.</summary>
internal interface IApprovalChannel
{
    /// <summary>Opens the request, or returns the existing one of the same requester and rule.</summary>
    Task<ApprovalChannelReply> EnsureAsync(ApprovalRequestWire request, CancellationToken ct);

    /// <summary>Reads the state of one request of the requester.</summary>
    Task<ApprovalChannelReply> GetAsync(string requestId, CancellationToken ct);
}
