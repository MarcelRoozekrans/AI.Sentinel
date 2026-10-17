using AI.Sentinel.Audit;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Approvals;

/// <summary>
/// <see cref="AuditingApprovalStore"/> over a store with an admin surface. <see cref="ApproveAsync"/> and
/// <see cref="DenyAsync"/> record the decision when the request was pending immediately before the call, so a
/// repeated or late call records nothing.
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

    public async ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct)
    {
        var pending = await FindPendingAsync(requestId, ct).ConfigureAwait(false);
        await _admin.ApproveAsync(requestId, approverId, note, ct).ConfigureAwait(false);
        if (pending is null)
        {
            return;
        }

        // Kept so that the expiry of this grant, observed later in this process, names its request.
        Remember(ApprovalAuditMemory.CallerPolicyKey(pending.CallerId, pending.PolicyName), requestId);
        Memory.Requests.TryRemove(requestId, out _);
        await WriteAsync(AuditEntryKinds.ApprovedPolicyCode, pending.PolicyName, pending.ToolName, requestId).ConfigureAwait(false);
    }

    public async ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct)
    {
        var pending = await FindPendingAsync(requestId, ct).ConfigureAwait(false);
        await _admin.DenyAsync(requestId, approverId, reason, ct).ConfigureAwait(false);
        if (pending is null)
        {
            return;
        }

        Memory.Requests.TryRemove(requestId, out _);
        await WriteAsync(AuditEntryKinds.DeniedPolicyCode, pending.PolicyName, pending.ToolName, requestId).ConfigureAwait(false);
    }

    public IAsyncEnumerable<PendingRequest> ListPendingAsync(CancellationToken ct) => _admin.ListPendingAsync(ct);
}
