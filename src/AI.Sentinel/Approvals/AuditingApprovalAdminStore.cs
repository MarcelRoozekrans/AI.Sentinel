using AI.Sentinel.Audit;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Approvals;

/// <summary>
/// <see cref="AuditingApprovalStore"/> over a store with an admin surface. <see cref="ApproveAsync"/> and
/// <see cref="DenyAsync"/> record the decision when the store reports <see cref="ApprovalDecisionOutcome.Applied"/>,
/// so a repeated, late or losing call records nothing.
/// </summary>
internal sealed class AuditingApprovalAdminStore : AuditingApprovalStore, IApprovalAdmin
{
    private readonly IApprovalAdmin _admin;

    internal AuditingApprovalAdminStore(
        IApprovalStore inner,
        IApprovalAdmin admin,
        IAuditStore audit,
        IAuditForwarder[] forwarders,
        ILogger? logger,
        ApprovalAuditMemory memory)
        : base(inner, audit, forwarders, logger, memory)
    {
        _admin = admin;
    }

    private protected override IApprovalAdmin? Admin => _admin;

    public async ValueTask<ApprovalDecisionOutcome> ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct)
    {
        var pending = await FindPendingAsync(requestId, ct).ConfigureAwait(false);
        var outcome = await _admin.ApproveAsync(requestId, approverId, note, ct).ConfigureAwait(false);
        if (TookEffect(outcome, requestId))
        {
            if (pending is not null)
            {
                // Kept so that the expiry of this grant, observed later in this process, names its request.
                Remember(ApprovalAuditMemory.CallerPolicyKey(pending.CallerId, pending.PolicyName), requestId);
            }
            var info = Describe(pending, requestId);
            Memory.Requests.TryRemove(requestId, out _);
            await WriteAsync(AuditEntryKinds.ApprovedPolicyCode, info.PolicyName, info.ToolName, requestId).ConfigureAwait(false);
        }
        return outcome;
    }

    public async ValueTask<ApprovalDecisionOutcome> DenyAsync(string requestId, string approverId, string reason, CancellationToken ct)
    {
        var pending = await FindPendingAsync(requestId, ct).ConfigureAwait(false);
        var outcome = await _admin.DenyAsync(requestId, approverId, reason, ct).ConfigureAwait(false);
        if (TookEffect(outcome, requestId))
        {
            var info = Describe(pending, requestId);
            Memory.Requests.TryRemove(requestId, out _);
            await WriteAsync(AuditEntryKinds.DeniedPolicyCode, info.PolicyName, info.ToolName, requestId).ConfigureAwait(false);
        }
        return outcome;
    }

    /// <summary>
    /// True when this call settled <paramref name="requestId"/> and this process has not recorded its outcome yet.
    /// The store decides atomically, so of two racing calls only one sees <see cref="ApprovalDecisionOutcome.Applied"/>.
    /// </summary>
    private bool TookEffect(ApprovalDecisionOutcome outcome, string requestId) =>
        outcome == ApprovalDecisionOutcome.Applied && Memory.Settled.TryAdd(requestId, 0);

    /// <summary>
    /// The policy and tool of a request this call settled: from the pending list read before the call, else from what
    /// this process saw the request opened with, else <c>unknown</c>. The list can miss a request when its read fails,
    /// and a settled decision is recorded all the same.
    /// </summary>
    private ApprovalAuditMemory.RequestInfo Describe(PendingRequest? pending, string requestId)
    {
        if (pending is not null)
        {
            return new ApprovalAuditMemory.RequestInfo(pending.PolicyName, pending.ToolName);
        }
        return Memory.Requests.TryGetValue(requestId, out var info) ? info : new ApprovalAuditMemory.RequestInfo(Unknown, Unknown);
    }

    public IAsyncEnumerable<PendingRequest> ListPendingAsync(CancellationToken ct) => _admin.ListPendingAsync(ct);
}
