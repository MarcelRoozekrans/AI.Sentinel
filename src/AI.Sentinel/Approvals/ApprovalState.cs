namespace AI.Sentinel.Approvals;

/// <summary>The state of an approval request. <see cref="IApprovalStore.EnsureRequestAsync"/>
/// always returns one of the three concrete subclasses.</summary>
public abstract record ApprovalState
{
    /// <summary>Closes the hierarchy: only the nested cases derive from it, so a new case is an additive change.</summary>
    private protected ApprovalState() { }

    /// <summary>An approval is currently active. The grant expires at <paramref name="ExpiresAt"/>.</summary>
    public sealed record Active(DateTimeOffset ExpiresAt) : ApprovalState;

    /// <summary>An approval is pending. The caller should wait or fail-with-receipt.</summary>
    public sealed record Pending(string RequestId, string ApprovalUrl, DateTimeOffset RequestedAt) : ApprovalState;

    /// <summary>The approval was denied or has expired.</summary>
    public sealed record Denied(string Reason, DateTimeOffset DeniedAt) : ApprovalState
    {
        /// <summary>
        /// The request that was denied or whose grant expired, when the store knows it. The built-in stores that own
        /// approval state, in-memory and SQLite, set it on every denial they return; it is <see langword="null"/> for a
        /// denial that belongs to no request, such as a caller the backend rejects, and for stores that do not set it.
        /// Approval decisions in the audit log are recorded under this id.
        /// </summary>
        public string? RequestId { get; init; }
    }
}
