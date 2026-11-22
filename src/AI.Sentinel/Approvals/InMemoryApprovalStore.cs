using System.Collections.Concurrent;
using System.Collections.Generic;
using AI.Sentinel.Authorization;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>In-process approval store. Single-process only; state is lost on restart.</summary>
public sealed class InMemoryApprovalStore : IApprovalStore, IApprovalAdmin
{
    private readonly ConcurrentDictionary<string, Entry> _byRequestId = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<(string callerId, string policyName), string> _dedupe =
        new(DedupeKeyComparer.Ordinal);
    // Per-key locks guarding the create-path.
    private readonly ConcurrentDictionary<(string callerId, string policyName), Lock> _keyLocks =
        new(DedupeKeyComparer.Ordinal);
    private readonly TimeProvider _time;

    public InMemoryApprovalStore() : this(TimeProvider.System) { }
    public InMemoryApprovalStore(TimeProvider time) { _time = time; }

    public ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(context);

        var key = (caller.Id, spec.PolicyName);
        if (_dedupe.TryGetValue(key, out var existingId) &&
            _byRequestId.TryGetValue(existingId, out var existing))
        {
            var state = StateOf(existing);
            if (state is ApprovalState.Denied)
            {
                // Terminal observed — clear dedupe so subsequent calls create a fresh request.
                // Use the (key, value) overload so we don't clobber a fresh request that another
                // thread may have just put in place.
                ((ICollection<KeyValuePair<(string callerId, string policyName), string>>)_dedupe)
                    .Remove(new KeyValuePair<(string callerId, string policyName), string>(key, existingId));
            }
            return ValueTask.FromResult(state);
        }

        // Per-key lock to prevent two concurrent callers from both creating an Entry and racing
        // last-writer-wins on the dedupe map (orphans the loser's Entry in _byRequestId).
        var lockObj = _keyLocks.GetOrAdd(key, static _ => new Lock());
        lock (lockObj)
        {
            // Re-check inside the lock (double-checked locking).
            if (_dedupe.TryGetValue(key, out existingId) &&
                _byRequestId.TryGetValue(existingId, out existing))
            {
                return ValueTask.FromResult(StateOf(existing));
            }

            var requestId = $"req-{Guid.NewGuid():N}";
            var now = _time.GetUtcNow();
            var entry = new Entry
            {
                RequestId = requestId,
                CallerId = caller.Id,
                PolicyName = spec.PolicyName,
                ToolName = context.ToolName,
                Args = context.Args,
                Justification = context.Justification,
                Reason = context.Reason,
                RequestedAt = now,
                GrantDuration = spec.GrantDuration,
                Status = EntryStatus.Pending,
                Decision = new TaskCompletionSource<ApprovalState>(TaskCreationOptions.RunContinuationsAsynchronously),
            };
            _byRequestId[requestId] = entry;
            _dedupe[key] = requestId;
            return ValueTask.FromResult<ApprovalState>(((ApprovalState.Pending)StateOf(entry)) with { IsNew = true });
        }
    }

    public async ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        if (!_byRequestId.TryGetValue(requestId, out var entry))
            return new ApprovalState.Denied("unknown request", _time.GetUtcNow()) { RequestId = requestId };
        if (entry.Status != EntryStatus.Pending) return StateOf(entry);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try { return await entry.Decision.Task.WaitAsync(cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return StateOf(entry); }
    }

    public ValueTask<ApprovalDecisionOutcome> ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ArgumentException.ThrowIfNullOrWhiteSpace(approverId);
        if (!_byRequestId.TryGetValue(requestId, out var entry))
            return ValueTask.FromResult(ApprovalDecisionOutcome.NotFound);
        lock (entry.Gate)
        {
            if (entry.Status != EntryStatus.Pending)
                return ValueTask.FromResult(ApprovalDecisionOutcome.AlreadySettled);
            entry.ApprovedAt = _time.GetUtcNow();
            entry.ApproverId = approverId;
            entry.ApproverNote = note;
            entry.Status = EntryStatus.Active;
        }
        entry.Decision.TrySetResult(StateOf(entry));
        return ValueTask.FromResult(ApprovalDecisionOutcome.Applied);
    }

    public ValueTask<ApprovalDecisionOutcome> DenyAsync(string requestId, string approverId, string reason, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ArgumentException.ThrowIfNullOrWhiteSpace(approverId);
        if (!_byRequestId.TryGetValue(requestId, out var entry))
            return ValueTask.FromResult(ApprovalDecisionOutcome.NotFound);
        lock (entry.Gate)
        {
            if (entry.Status != EntryStatus.Pending)
                return ValueTask.FromResult(ApprovalDecisionOutcome.AlreadySettled);
            entry.DenyReason = reason;
            entry.DeniedAt = _time.GetUtcNow();
            entry.ApproverId = approverId;
            entry.Status = EntryStatus.Denied;
        }
        entry.Decision.TrySetResult(StateOf(entry));
        return ValueTask.FromResult(ApprovalDecisionOutcome.Applied);
    }

    public async IAsyncEnumerable<PendingRequest> ListPendingAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var entry in _byRequestId.Values)
        {
            ct.ThrowIfCancellationRequested();
            if (entry.Status == EntryStatus.Pending)
                yield return new PendingRequest(entry.RequestId, entry.CallerId, entry.PolicyName,
                    entry.ToolName, entry.Args, entry.RequestedAt, entry.Justification)
                {
                    Reason = entry.Reason,
                };
        }
    }

    private ApprovalState StateOf(Entry e)
    {
        var now = _time.GetUtcNow();
        return e.Status switch
        {
            EntryStatus.Active when e.ApprovedAt is { } a && a + e.GrantDuration > now
                => new ApprovalState.Active(a + e.GrantDuration) { RequestId = e.RequestId },
            EntryStatus.Active
                => new ApprovalState.Denied("expired", now) { RequestId = e.RequestId },
            EntryStatus.Denied
                => new ApprovalState.Denied(e.DenyReason ?? "denied", e.DeniedAt ?? now) { RequestId = e.RequestId },
            _ => new ApprovalState.Pending(e.RequestId, $"sentinel://approve/{e.RequestId}", e.RequestedAt) { Reason = e.Reason },
        };
    }

    private enum EntryStatus { Pending, Active, Denied }

    private sealed class DedupeKeyComparer : IEqualityComparer<(string callerId, string policyName)>
    {
        public static readonly DedupeKeyComparer Ordinal = new();

        public bool Equals((string callerId, string policyName) x, (string callerId, string policyName) y) =>
            string.Equals(x.callerId, y.callerId, StringComparison.Ordinal) &&
            string.Equals(x.policyName, y.policyName, StringComparison.Ordinal);

        public int GetHashCode((string callerId, string policyName) obj) =>
            HashCode.Combine(
                StringComparer.Ordinal.GetHashCode(obj.callerId),
                StringComparer.Ordinal.GetHashCode(obj.policyName));
    }

    private sealed class Entry
    {
        /// <summary>Makes the pending check and the decision of <see cref="ApproveAsync"/> and
        /// <see cref="DenyAsync"/> one step, so only one of two concurrent decisions applies.</summary>
        public Lock Gate { get; } = new();
        public required string RequestId { get; init; }
        public required string CallerId { get; init; }
        public required string PolicyName { get; init; }
        public required string ToolName { get; init; }
        public System.Text.Json.JsonElement Args { get; init; }
        public string? Justification { get; init; }
        public string? Reason { get; init; }
        public DateTimeOffset RequestedAt { get; init; }
        public TimeSpan GrantDuration { get; init; }
        public EntryStatus Status { get; set; }
        public DateTimeOffset? ApprovedAt { get; set; }
        public DateTimeOffset? DeniedAt { get; set; }
        public string? DenyReason { get; set; }
        public string? ApproverId { get; set; }
        public string? ApproverNote { get; set; }
        public required TaskCompletionSource<ApprovalState> Decision { get; init; }
    }
}
