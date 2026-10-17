using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.Logging;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Wraps an <see cref="IApprovalStore"/> and records each decision it observes as an informational, hash-chained audit
/// entry: an expired grant and a wait that times out, and for a store whose decisions are made elsewhere, such as Entra
/// PIM, the approval or denial it reports. Decisions made through <see cref="IApprovalAdmin"/> are recorded by
/// <see cref="AuditingApprovalAdminStore"/>. The entry is written after the inner call succeeds; a failed write is
/// logged and never fails the decision. Behaviour is otherwise the inner store's.
/// </summary>
internal class AuditingApprovalStore : IApprovalStore
{
    /// <summary>Stands in for a policy, tool or request id this process never saw.</summary>
    private const string Unknown = "unknown";

    /// <summary>Reason of the <see cref="ApprovalState.Denied"/> the stores return for a grant that ran out.</summary>
    private const string ExpiredReason = "expired";

    private readonly IApprovalStore _inner;
    private readonly IAuditStore _audit;
    private readonly IAuditForwarder[] _forwarders;
    private readonly ILogger? _logger;

    internal AuditingApprovalStore(
        IApprovalStore inner,
        IAuditStore audit,
        IAuditForwarder[] forwarders,
        ILogger? logger,
        ApprovalAuditMemory memory)
    {
        _inner = inner;
        _audit = audit;
        _forwarders = forwarders;
        _logger = logger;
        Memory = memory;
    }

    /// <summary>What this process has seen of the inner store's requests, shared by every wrapper over it.</summary>
    private protected ApprovalAuditMemory Memory { get; }

    /// <summary>The admin surface of the inner store, or <see langword="null"/> when it has none.</summary>
    private protected virtual IApprovalAdmin? Admin => null;

    public async ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
    {
        var state = await _inner.EnsureRequestAsync(caller, spec, context, ct).ConfigureAwait(false);

        // The inner store validated its arguments, so they are not null here.
        var key = ApprovalAuditMemory.CallerPolicyKey(caller.Id, spec.PolicyName);
        switch (state)
        {
            case ApprovalState.Pending p:
                Memory.Requests[p.RequestId] = new ApprovalAuditMemory.RequestInfo(spec.PolicyName, context.ToolName);
                Remember(key, p.RequestId);
                break;

            case ApprovalState.Denied d:
                // The stores forget a settled request when they report it, so a grant reported expired is reported once.
                Memory.RequestIdByCallerPolicy.TryRemove(key, out var requestId);
                if (requestId is not null)
                {
                    Memory.Requests.TryRemove(requestId, out _);
                }
                if (string.Equals(d.Reason, ExpiredReason, StringComparison.Ordinal))
                {
                    await WriteAsync(AuditEntryKinds.ExpiredPolicyCode, spec.PolicyName, context.ToolName, requestId ?? Unknown)
                        .ConfigureAwait(false);
                }
                break;
        }
        return state;
    }

    public async ValueTask<ApprovalState> WaitForDecisionAsync(string requestId, TimeSpan timeout, CancellationToken ct)
    {
        var state = await _inner.WaitForDecisionAsync(requestId, timeout, ct).ConfigureAwait(false);

        if (state is ApprovalState.Pending)
        {
            // Still pending at the deadline. A wait the caller cancelled did not time out.
            if (!ct.IsCancellationRequested)
            {
                await WriteForAsync(AuditEntryKinds.TimedOutPolicyCode, requestId, ct).ConfigureAwait(false);
            }
            return state;
        }

        // A store with an admin surface reports here what ApproveAsync or DenyAsync already recorded.
        if (Admin is null && Memory.Settled.TryAdd(requestId, 0))
        {
            var code = state is ApprovalState.Active ? AuditEntryKinds.ApprovedPolicyCode : AuditEntryKinds.DeniedPolicyCode;
            await WriteForAsync(code, requestId, ct).ConfigureAwait(false);
            Memory.Requests.TryRemove(requestId, out _);
        }
        return state;
    }

    /// <summary>Records <paramref name="requestId"/> as the latest request of its caller and policy, and forgets the one it replaces.</summary>
    private protected void Remember(string callerPolicyKey, string requestId)
    {
        string? replaced = null;
        Memory.RequestIdByCallerPolicy.AddOrUpdate(
            callerPolicyKey,
            requestId,
            (_, previous) =>
            {
                replaced = previous;
                return requestId;
            });
        if (replaced is not null && !string.Equals(replaced, requestId, StringComparison.Ordinal))
        {
            Memory.Requests.TryRemove(replaced, out _);
        }
    }

    /// <summary>Writes the decision of <paramref name="requestId"/> with the policy and tool this process saw it opened with.</summary>
    private async ValueTask WriteForAsync(string policyCode, string requestId, CancellationToken ct)
    {
        if (!Memory.Requests.TryGetValue(requestId, out var info))
        {
            var pending = await FindPendingAsync(requestId, ct).ConfigureAwait(false);
            info = pending is null
                ? new ApprovalAuditMemory.RequestInfo(Unknown, Unknown)
                : new ApprovalAuditMemory.RequestInfo(pending.PolicyName, pending.ToolName);
        }
        await WriteAsync(policyCode, info.PolicyName, info.ToolName, requestId).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the pending request <paramref name="requestId"/> from the inner store's admin surface, or returns
    /// <see langword="null"/> when it is not pending, the store has no admin surface or the read fails.
    /// </summary>
    private protected async ValueTask<PendingRequest?> FindPendingAsync(string requestId, CancellationToken ct)
    {
        if (Admin is not { } admin)
        {
            return null;
        }

        try
        {
            await foreach (var pending in admin.ListPendingAsync(ct).ConfigureAwait(false))
            {
                if (string.Equals(pending.RequestId, requestId, StringComparison.Ordinal))
                {
                    return pending;
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // Auditing must never fail the decision; the failure is logged.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger?.LogError(ex, "Could not read approval request {RequestId} for the audit log.", requestId);
        }
        return null;
    }

    /// <summary>
    /// Appends the decision entry and forwards it. Uses <see cref="CancellationToken.None"/>: the decision has been
    /// made, so its record must not be lost to a cancelled request. A failure is logged and never thrown.
    /// </summary>
    private protected async ValueTask WriteAsync(string policyCode, string policyName, string toolName, string requestId)
    {
        try
        {
            var entry = ApprovalStoreAuditing.Decision(policyCode, policyName, toolName, requestId);
            await _audit.AppendAndForwardAsync(entry, _forwarders, CancellationToken.None).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Auditing must never fail the decision; the failure is logged.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger?.LogError(ex, "Could not write the {PolicyCode} audit entry for approval request {RequestId}.", policyCode, requestId);
        }
    }
}
