using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Pluggable approval backend. Implementations: <see cref="InMemoryApprovalStore"/> in core,
/// <c>SqliteApprovalStore</c> in <c>AI.Sentinel.Approvals.Sqlite</c>, <c>EntraPimApprovalStore</c>
/// in <c>AI.Sentinel.Approvals.EntraPim</c>.
/// </summary>
public interface IApprovalStore
{
    /// <summary>
    /// Returns the current state for <c>(caller, spec.PolicyName)</c>. Idempotent: repeated calls
    /// during a pending or active grant return the same state without creating duplicate requests.
    /// </summary>
    ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller,
        ApprovalSpec spec,
        ApprovalContext context,
        CancellationToken ct);

    /// <summary>
    /// Blocks until the named request transitions to <see cref="ApprovalState.Active"/> or
    /// <see cref="ApprovalState.Denied"/>, or the timeout elapses (returns the most recent state).
    /// </summary>
    ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId,
        TimeSpan timeout,
        CancellationToken ct);
}
