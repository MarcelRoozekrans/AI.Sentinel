namespace AI.Sentinel.Approvals;

/// <summary>
/// Admin surface for stores that own approval state (InMemory, Sqlite). EntraPim does NOT
/// implement this — approvals happen in the PIM portal. Dashboard checks
/// <c>store is IApprovalAdmin</c> to decide whether to render Approve/Deny buttons.
/// </summary>
public interface IApprovalAdmin
{
    ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct);
    ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct);
    IAsyncEnumerable<PendingRequest> ListPendingAsync(CancellationToken ct);
}
