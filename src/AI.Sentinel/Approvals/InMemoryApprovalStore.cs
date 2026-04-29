using System.Collections.Concurrent;
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>In-process approval store. Single-process only; state is lost on restart.</summary>
public sealed class InMemoryApprovalStore : IApprovalStore, IApprovalAdmin
{
    private readonly ConcurrentDictionary<string, Entry> _byRequestId = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<(string callerId, string policyName), string> _dedupe =
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
            RequestedAt = now,
            GrantDuration = spec.GrantDuration,
            Status = EntryStatus.Pending,
            Decision = new TaskCompletionSource<ApprovalState>(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        _byRequestId[requestId] = entry;
        _dedupe[key] = requestId;
        return ValueTask.FromResult(StateOf(entry));
    }

    public async ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        if (!_byRequestId.TryGetValue(requestId, out var entry))
            return new ApprovalState.Denied("unknown request", _time.GetUtcNow());
        if (entry.Status != EntryStatus.Pending) return StateOf(entry);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try { return await entry.Decision.Task.WaitAsync(cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return StateOf(entry); }
    }

    public ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        if (_byRequestId.TryGetValue(requestId, out var entry) && entry.Status == EntryStatus.Pending)
        {
            entry.Status = EntryStatus.Active;
            entry.ApprovedAt = _time.GetUtcNow();
            entry.Decision.TrySetResult(StateOf(entry));
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        if (_byRequestId.TryGetValue(requestId, out var entry) && entry.Status == EntryStatus.Pending)
        {
            entry.Status = EntryStatus.Denied;
            entry.DenyReason = reason;
            entry.DeniedAt = _time.GetUtcNow();
            entry.Decision.TrySetResult(StateOf(entry));
        }
        return ValueTask.CompletedTask;
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
                    entry.ToolName, entry.Args, entry.RequestedAt, entry.Justification);
        }
    }

    private ApprovalState StateOf(Entry e)
    {
        var now = _time.GetUtcNow();
        return e.Status switch
        {
            EntryStatus.Active when e.ApprovedAt is { } a && a + e.GrantDuration > now
                => new ApprovalState.Active(a + e.GrantDuration),
            EntryStatus.Active
                => new ApprovalState.Denied("expired", now),
            EntryStatus.Denied
                => new ApprovalState.Denied(e.DenyReason ?? "denied", e.DeniedAt ?? now),
            _ => new ApprovalState.Pending(e.RequestId, $"sentinel://approve/{e.RequestId}", e.RequestedAt),
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
        public required string RequestId { get; init; }
        public required string CallerId { get; init; }
        public required string PolicyName { get; init; }
        public required string ToolName { get; init; }
        public System.Text.Json.JsonElement Args { get; init; }
        public string? Justification { get; init; }
        public DateTimeOffset RequestedAt { get; init; }
        public TimeSpan GrantDuration { get; init; }
        public EntryStatus Status { get; set; }
        public DateTimeOffset? ApprovedAt { get; set; }
        public DateTimeOffset? DeniedAt { get; set; }
        public string? DenyReason { get; set; }
        public required TaskCompletionSource<ApprovalState> Decision { get; init; }
    }
}
