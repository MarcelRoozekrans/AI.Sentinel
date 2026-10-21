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

    /// <summary>How far the clocks of two processes sharing an audit store may disagree.</summary>
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

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
                Memory.Requests[p.RequestId] = new ApprovalAuditMemory.RequestInfo(spec.PolicyName, context.ToolName, spec.GrantDuration);
                Remember(key, p.RequestId);
                break;

            case ApprovalState.Active a when Admin is null:
                // A store whose decisions are made elsewhere, such as Entra PIM, reports the grant here to a hook or a
                // fail-fast proxy that never waits. The store's id wins; the remembered one covers stores without it.
                var grantedId = a.RequestId
                    ?? (Memory.RequestIdByCallerPolicy.TryGetValue(key, out var rememberedGrant) ? rememberedGrant : null);
                if (grantedId is not null && Memory.Settled.TryAdd(grantedId, 0))
                {
                    Memory.Requests.TryRemove(grantedId, out _);
                    await WriteApprovedOnceAsync(a, spec.GrantDuration, spec.PolicyName, context.ToolName, grantedId)
                        .ConfigureAwait(false);
                }
                break;

            case ApprovalState.Denied d:
                // The stores forget a settled request when they report it, so a grant reported expired is reported once.
                // The store's own id wins; the remembered one covers stores that do not set it.
                Memory.RequestIdByCallerPolicy.TryRemove(key, out var remembered);
                var requestId = d.RequestId ?? remembered;
                var expired = string.Equals(d.Reason, ExpiredReason, StringComparison.Ordinal);
                if (requestId is not null)
                {
                    Memory.Requests.TryRemove(requestId, out _);

                    // For an admin store Settled only guards ApproveAsync and DenyAsync against writing twice; the
                    // store has now forgotten the request, so neither can settle it again. For a store whose decisions
                    // are made elsewhere it guards a grant against being recorded on every call, so it is dropped only
                    // when the request is over: an expiry, or a denial that names its request. A denial of no request,
                    // such as a Graph error, says nothing about the grant.
                    if (Admin is not null || expired || d.RequestId is not null)
                    {
                        Memory.Settled.TryRemove(requestId, out _);
                    }
                }
                if (expired)
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
            // Still pending at the deadline. A wait the caller cancelled did not time out. The request stays open,
            // so what this process remembers of it is kept.
            if (!ct.IsCancellationRequested)
            {
                var info = await LookUpAsync(requestId, ct).ConfigureAwait(false);
                await WriteAsync(AuditEntryKinds.TimedOutPolicyCode, info.PolicyName, info.ToolName, requestId).ConfigureAwait(false);
            }
            return state;
        }

        // A store with an admin surface reports here what ApproveAsync or DenyAsync already recorded.
        if (Admin is null)
        {
            // The remembered row is keyed by the id this process waited on; the entry names the store's id, which is
            // the same one for every built-in store. A denial without a request id belongs to no request, such as a
            // Graph error while polling Entra PIM: it is not a decision, so nothing is recorded and a later outcome
            // of the same request still is.
            var settledId = state switch
            {
                ApprovalState.Active a => a.RequestId ?? requestId,
                ApprovalState.Denied d => d.RequestId,
                _ => null,
            };
            if (settledId is not null && Memory.Settled.TryAdd(settledId, 0))
            {
                var info = await LookUpAsync(requestId, ct).ConfigureAwait(false);
                Memory.Requests.TryRemove(requestId, out _);
                if (state is ApprovalState.Active granted)
                {
                    await WriteApprovedOnceAsync(granted, info.GrantDuration, info.PolicyName, info.ToolName, settledId)
                        .ConfigureAwait(false);
                }
                else
                {
                    await WriteAsync(AuditEntryKinds.DeniedPolicyCode, info.PolicyName, info.ToolName, settledId).ConfigureAwait(false);
                }
            }
        }
        return state;
    }

    /// <summary>
    /// Records <paramref name="requestId"/> as the latest request of its caller and policy, and forgets the one it
    /// replaces; for a store without an admin surface that includes its settled outcome.
    /// </summary>
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
            if (Admin is null)
            {
                // A store whose decisions are made elsewhere, such as Entra PIM, reports neither an expiry nor a
                // denial here: the caller's next request opens a new one, which ends the old one for this process.
                Memory.Settled.TryRemove(replaced, out _);
            }
        }
    }

    /// <summary>The policy and tool this process saw <paramref name="requestId"/> opened with, read from the store's
    /// pending list when this process never saw it, and <c>unknown</c> when neither knows it.</summary>
    private async ValueTask<ApprovalAuditMemory.RequestInfo> LookUpAsync(string requestId, CancellationToken ct)
    {
        if (Memory.Requests.TryGetValue(requestId, out var info))
        {
            return info;
        }
        var pending = await FindPendingAsync(requestId, ct).ConfigureAwait(false);
        return pending is null
            ? new ApprovalAuditMemory.RequestInfo(Unknown, Unknown)
            : new ApprovalAuditMemory.RequestInfo(pending.PolicyName, pending.ToolName);
    }

    /// <summary>
    /// The state of <paramref name="requestId"/> right now, read without waiting, or <see langword="null"/> when the
    /// read fails. Uses <see cref="CancellationToken.None"/>: the decision has been taken, and recording it must not
    /// depend on the caller's token.
    /// </summary>
    private protected async ValueTask<ApprovalState?> ReadStateAsync(string requestId)
    {
        try
        {
            return await _inner.WaitForDecisionAsync(requestId, TimeSpan.Zero, CancellationToken.None).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Auditing must never fail the decision; the failure is logged.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger?.LogError(ex, "Could not read the state of approval request {RequestId} for the audit log.", requestId);
            return null;
        }
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
    /// Records the grant <paramref name="requestId"/> of a store whose decisions are made elsewhere, unless another
    /// process has already recorded it. Each hook invocation is a new process that remembers nothing, so the first time
    /// this process sees a grant it looks for an earlier <c>APPROVED</c> entry of the request in the audit store.
    /// </summary>
    /// <param name="granted">The grant the store reported.</param>
    /// <param name="grantDuration">The duration the request asked for, or <see langword="null"/> when unknown.</param>
    /// <param name="policyName">The approval policy.</param>
    /// <param name="toolName">The gated tool.</param>
    /// <param name="requestId">The approval request.</param>
    private async ValueTask WriteApprovedOnceAsync(
        ApprovalState.Active granted, TimeSpan? grantDuration, string policyName, string toolName, string requestId)
    {
        // An earlier entry was written while the grant was active, so no earlier than the grant's start. The query
        // starts there, less the clock skew, and reads the whole log only when the requested duration is unknown.
        DateTimeOffset? since = null;
        if (grantDuration is { } duration)
        {
            var start = granted.ExpiresAt - duration;
            var now = DateTimeOffset.UtcNow;
            since = (start < now ? start : now) - ClockSkew;
        }

        if (!await IsApprovalRecordedAsync(requestId, since).ConfigureAwait(false))
        {
            await WriteAsync(AuditEntryKinds.ApprovedPolicyCode, policyName, toolName, requestId).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// True when the audit store holds an <c>APPROVED</c> entry of <paramref name="requestId"/> timestamped at or after
    /// <paramref name="since"/>. A failed read is logged and returns <see langword="false"/>: a duplicate entry is
    /// better than a missing decision. Uses <see cref="CancellationToken.None"/>, as <see cref="WriteAsync"/> does.
    /// </summary>
    private async ValueTask<bool> IsApprovalRecordedAsync(string requestId, DateTimeOffset? since)
    {
        // The built-in stores filter on the detector and the policy code; a custom store may return a superset, so both
        // are checked again below. The read runs newest first and stops at the window edge, rather than passing the
        // window as From, so SQLite walks the detector index without a timestamp range scan.
        var query = new AuditQuery
        {
            DetectorId = AuditEntryKinds.ApprovalDetectorId,
            PolicyCode = AuditEntryKinds.ApprovedPolicyCode,
            PageSize = int.MaxValue,
            Reverse = true,
        };
        try
        {
            await foreach (var entry in _audit.QueryAsync(query, CancellationToken.None).ConfigureAwait(false))
            {
                if (entry.Timestamp < since)
                {
                    break;
                }
                if (string.Equals(entry.DetectorId, AuditEntryKinds.ApprovalDetectorId, StringComparison.Ordinal)
                    && string.Equals(entry.PolicyCode, AuditEntryKinds.ApprovedPolicyCode, StringComparison.Ordinal)
                    && string.Equals(ApprovalStoreAuditing.RequestIdOf(entry.Summary), requestId, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }
#pragma warning disable CA1031 // Auditing must never fail the decision; the failure is logged.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger?.LogWarning(
                ex, "Could not look for an earlier APPROVED audit entry of approval request {RequestId}; recording it.", requestId);
        }
        return false;
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
