using System.Text.Json;

namespace AI.Sentinel.AspNetCore.ServerApprovals;

/// <summary>
/// The approval requests of the server part (#662), in memory. A request is identified by its requester, its repository and its rule, so a hook that
/// asks again, as an agent does when it retries, finds the open request instead of making another. A request that is decided is
/// deleted <see cref="Retention"/> after it was decided; one that is still pending is kept. A restart of the server loses the requests,
/// and a hook that asks again opens a new one.
/// </summary>
internal sealed class ServerApprovalStore(TimeProvider time)
{
    /// <summary>How long a decided request is kept, after the decision.</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromDays(30);

    /// <summary>The current time of the store, which decides whether a grant still holds.</summary>
    public DateTimeOffset Now => time.GetUtcNow();

    private readonly Lock _gate = new();
    private readonly Dictionary<string, Entry> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Requester, string Repository, string Policy), string> _open = [];

    /// <summary>Opens a request for <paramref name="requester"/>, <paramref name="repository"/> and <paramref name="policy"/>, or returns the open one. A request that
    /// was denied, or whose grant ran out, is returned once more, so the agent sees why, and the next call opens a new request.</summary>
    public ServerApprovalEnsure Ensure(
        string requester, string repository, string policy, string tool, JsonElement args, string? justification, string? reason, TimeSpan grant)
    {
        lock (_gate)
        {
            var now = time.GetUtcNow();
            Purge(now);
            var key = (requester, repository, policy);
            if (_open.TryGetValue(key, out var openId) && _byId.TryGetValue(openId, out var open))
            {
                var snapshot = open.Snapshot();
                var ended = snapshot.Status == ServerApprovalStatus.Denied || (snapshot.ExpiresAt is { } end && end <= now);
                if (ended)
                {
                    _open.Remove(key);
                }

                return new ServerApprovalEnsure(snapshot, IsNew: false);
            }

            var entry = new Entry
            {
                Id = $"req-{Guid.NewGuid():N}",
                Requester = requester,
                Repository = repository,
                Policy = policy,
                Tool = tool,
                Args = args.ValueKind == JsonValueKind.Undefined ? null : args.Clone(),
                Justification = justification,
                RequestReason = reason,
                RequestedAt = now,
                GrantDuration = grant,
            };
            _byId[entry.Id] = entry;
            _open[key] = entry.Id;
            return new ServerApprovalEnsure(entry.Snapshot(), IsNew: true);
        }
    }

    /// <summary>The request, or <see langword="null"/> when there is none or it was deleted.</summary>
    public ServerApproval? Find(string id)
    {
        lock (_gate)
        {
            Purge(time.GetUtcNow());
            return _byId.TryGetValue(id, out var entry) ? entry.Snapshot() : null;
        }
    }

    /// <summary>The requests that are not decided yet, oldest first.</summary>
    public IReadOnlyList<ServerApproval> Pending()
    {
        lock (_gate)
        {
            Purge(time.GetUtcNow());
            return [.. _byId.Values.Where(e => e.Status == ServerApprovalStatus.Pending).Select(e => e.Snapshot()).OrderBy(a => a.RequestedAt)];
        }
    }

    /// <summary>Every request of <paramref name="requester"/>, newest first.</summary>
    public IReadOnlyList<ServerApproval> OfRequester(string requester)
    {
        lock (_gate)
        {
            Purge(time.GetUtcNow());
            return [.. _byId.Values.Where(e => string.Equals(e.Requester, requester, StringComparison.Ordinal)).Select(e => e.Snapshot()).OrderByDescending(a => a.RequestedAt)];
        }
    }

    /// <summary>Settles a pending request. Checking that it is pending and settling it is one step, so of two concurrent decisions exactly
    /// one wins. The request after the decision, or <see langword="null"/> when it was not pending or does not exist.</summary>
    public ServerApproval? Decide(string id, bool approve, string decider, string? text)
    {
        lock (_gate)
        {
            var now = time.GetUtcNow();
            Purge(now);
            if (!_byId.TryGetValue(id, out var entry) || entry.Status != ServerApprovalStatus.Pending)
            {
                return null;
            }

            entry.Status = approve ? ServerApprovalStatus.Approved : ServerApprovalStatus.Denied;
            entry.DecidedAt = now;
            entry.Decider = decider;
            entry.Note = text;
            return entry.Snapshot();
        }
    }

    /// <summary>Deletes the decided requests that are past <see cref="Retention"/>, whether or not anyone calls the store.</summary>
    public void PurgeExpired()
    {
        lock (_gate)
        {
            Purge(time.GetUtcNow());
        }
    }

    /// <summary>The number of requests held.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _byId.Count;
            }
        }
    }

    // Called under the gate.
    private void Purge(DateTimeOffset now)
    {
        var expired = _byId.Values.Where(e => e.DecidedAt is { } at && at + Retention <= now).Select(e => e.Id).ToList();
        foreach (var id in expired)
        {
            var entry = _byId[id];
            _byId.Remove(id);
            var key = (entry.Requester, entry.Repository, entry.Policy);
            if (_open.TryGetValue(key, out var openId) && string.Equals(openId, id, StringComparison.Ordinal))
            {
                _open.Remove(key);
            }
        }
    }

    private sealed class Entry
    {
        public required string Id { get; init; }
        public required string Requester { get; init; }
        public required string Repository { get; init; }
        public required string Policy { get; init; }
        public required string Tool { get; init; }
        public JsonElement? Args { get; init; }
        public string? Justification { get; init; }
        public string? RequestReason { get; init; }
        public DateTimeOffset RequestedAt { get; init; }
        public TimeSpan GrantDuration { get; init; }
        public ServerApprovalStatus Status { get; set; }
        public DateTimeOffset? DecidedAt { get; set; }
        public string? Decider { get; set; }
        public string? Note { get; set; }

        public ServerApproval Snapshot() =>
            new(Id, Requester, Repository, Policy, Tool, Args, Justification, RequestReason, RequestedAt, GrantDuration, Status, DecidedAt, Decider, Note);
    }
}
