namespace AI.Sentinel.Approvals;

/// <summary>The state of an approval request. <see cref="IApprovalStore.EnsureRequestAsync"/>
/// always returns one of the three concrete subclasses.</summary>
public abstract record ApprovalState
{
    /// <summary>An approval is currently active. The grant expires at <paramref name="ExpiresAt"/>.</summary>
    public sealed record Active(DateTimeOffset ExpiresAt) : ApprovalState;

    /// <summary>An approval is pending. The caller should wait or fail-with-receipt.</summary>
    public sealed record Pending(string RequestId, string ApprovalUrl, DateTimeOffset RequestedAt) : ApprovalState;

    /// <summary>The approval was denied or has expired.</summary>
    public sealed record Denied(string Reason, DateTimeOffset DeniedAt) : ApprovalState;
}
