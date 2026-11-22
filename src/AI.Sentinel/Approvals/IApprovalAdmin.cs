namespace AI.Sentinel.Approvals;

/// <summary>
/// Admin surface for stores that own approval state (InMemory, Sqlite). EntraPim does NOT
/// implement this — approvals happen in the PIM portal. Dashboard checks
/// <c>store is IApprovalAdmin</c> to decide whether to render Approve/Deny buttons.
/// </summary>
public interface IApprovalAdmin
{
    /// <summary>Approves a pending request. Checking that the request is pending and settling it is one atomic step,
    /// so of two concurrent decisions on one request exactly one returns <see cref="ApprovalDecisionOutcome.Applied"/>.</summary>
    /// <returns><see cref="ApprovalDecisionOutcome.Applied"/> when this call approved the request,
    /// <see cref="ApprovalDecisionOutcome.AlreadySettled"/> when it was no longer pending, and
    /// <see cref="ApprovalDecisionOutcome.NotFound"/> when the store does not know the id.</returns>
    ValueTask<ApprovalDecisionOutcome> ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct);

    /// <summary>Denies a pending request, with the same atomicity and outcomes as <see cref="ApproveAsync"/>.</summary>
    ValueTask<ApprovalDecisionOutcome> DenyAsync(string requestId, string approverId, string reason, CancellationToken ct);
    IAsyncEnumerable<PendingRequest> ListPendingAsync(CancellationToken ct);
}
