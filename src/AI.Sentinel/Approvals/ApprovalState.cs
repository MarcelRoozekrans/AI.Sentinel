namespace AI.Sentinel.Approvals;

/// <summary>The state of an approval request. <see cref="IApprovalStore.EnsureRequestAsync"/>
/// always returns one of the three concrete subclasses.</summary>
public abstract record ApprovalState
{
    /// <summary>Closes the hierarchy: only the nested cases derive from it, so a new case is an additive change.</summary>
    private protected ApprovalState() { }

    /// <summary>An approval is currently active. The grant expires at <paramref name="ExpiresAt"/>.</summary>
    public sealed record Active(DateTimeOffset ExpiresAt) : ApprovalState
    {
        /// <summary>
        /// The request whose approval granted this access, when the store knows it. The built-in stores set it whenever
        /// they know the id: in-memory and SQLite on every grant they return, Entra PIM from the request it waited on or
        /// the request that created the active assignment. It is <see langword="null"/> for stores that do not set it.
        /// Approval decisions in the audit log are recorded under this id.
        /// </summary>
        public string? RequestId { get; init; }
    }

    /// <summary>An approval is pending. The caller should wait or fail-with-receipt.</summary>
    public sealed record Pending(string RequestId, string ApprovalUrl, DateTimeOffset RequestedAt) : ApprovalState
    {
        /// <summary>
        /// <see langword="true"/> only on the <see cref="IApprovalStore.EnsureRequestAsync"/> call that created this
        /// request. <see cref="IApprovalStore.WaitForDecisionAsync"/> and every reuse of an existing request return
        /// <see langword="false"/>. A store that does not set it gets no approval notifications.
        /// </summary>
        public bool IsNew { get; init; }
    }

    /// <summary>The approval was denied or has expired.</summary>
    public sealed record Denied(string Reason, DateTimeOffset DeniedAt) : ApprovalState
    {
        /// <summary>
        /// The request that was denied or whose grant expired, when the store knows it. The built-in stores that own
        /// approval state, in-memory and SQLite, set it on every denial they return, and Entra PIM on a denial PIM
        /// reports for the request it waited on. It is <see langword="null"/> for a denial that belongs to no request,
        /// such as a caller the backend rejects or a Graph error while polling, and for stores that do not set it.
        /// Approval decisions in the audit log are recorded under this id; a denial without one is not recorded as a
        /// decision.
        /// </summary>
        public string? RequestId { get; init; }
    }
}
