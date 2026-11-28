namespace AI.Sentinel.AspNetCore.Events;

/// <summary>The in-memory <see cref="IServerEventStore"/>. Data lives as long as the process; a persistent store is a separate piece of work.</summary>
internal sealed class InMemoryServerEventStore : IServerEventStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, OrganisationData> _byOrganisation = new(StringComparer.Ordinal);

    public ValueTask<bool> AddAsync(ServerEvent serverEvent, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(serverEvent);
        ct.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var data = Of(serverEvent.Organisation);
            if (!data.Ids.Add(serverEvent.Id))
            {
                return ValueTask.FromResult(false);
            }

            data.Events.Add(serverEvent);
            var key = (DateOnly.FromDateTime(serverEvent.ReceivedAt.UtcDateTime), serverEvent.Outcome);
            data.Counts[key] = data.Counts.GetValueOrDefault(key) + 1;
            return ValueTask.FromResult(true);
        }
    }

    public ValueTask AddGapAsync(ServerEventGap gap, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(gap);
        lock (_gate)
        {
            var gaps = Of(gap.Organisation).Gaps;
            if (gap.Id is null || !gaps.Exists(g => string.Equals(g.Id, gap.Id, StringComparison.Ordinal) && string.Equals(g.Developer, gap.Developer, StringComparison.Ordinal)))
            {
                gaps.Add(gap);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask AddDroppedAsync(string organisation, IReadOnlyDictionary<string, int> names, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(names);
        lock (_gate)
        {
            var dropped = Of(organisation).Dropped;
            foreach (var (name, count) in names)
            {
                dropped[name] = dropped.GetValueOrDefault(name) + count;
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask<IReadOnlyList<ServerEvent>> ReadEventsAsync(string organisation, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<ServerEvent> copy = _byOrganisation.TryGetValue(organisation, out var d) ? [.. d.Events] : [];
            return ValueTask.FromResult(copy);
        }
    }

    public ValueTask<IReadOnlyList<ServerEventGap>> ReadGapsAsync(string organisation, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<ServerEventGap> copy = _byOrganisation.TryGetValue(organisation, out var d) ? [.. d.Gaps] : [];
            return ValueTask.FromResult(copy);
        }
    }

    public ValueTask<IReadOnlyList<DailyCount>> ReadDailyCountsAsync(string organisation, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<DailyCount> copy = _byOrganisation.TryGetValue(organisation, out var d)
                ? [.. d.Counts.Select(c => new DailyCount(c.Key.Day, c.Key.Outcome, c.Value)).OrderBy(c => c.Day).ThenBy(c => c.Outcome, StringComparer.Ordinal)]
                : [];
            return ValueTask.FromResult(copy);
        }
    }

    public ValueTask<IReadOnlyDictionary<string, int>> ReadDroppedAsync(string organisation, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyDictionary<string, int> copy = _byOrganisation.TryGetValue(organisation, out var d)
                ? new Dictionary<string, int>(d.Dropped, StringComparer.Ordinal)
                : new Dictionary<string, int>(StringComparer.Ordinal);
            return ValueTask.FromResult(copy);
        }
    }

    public ValueTask PruneAsync(string organisation, DateTimeOffset eventsBefore, DateOnly countsBefore, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_byOrganisation.TryGetValue(organisation, out var data))
            {
                return ValueTask.CompletedTask;
            }

            foreach (var gone in data.Events.Where(e => e.ReceivedAt < eventsBefore))
            {
                data.Ids.Remove(gone.Id);
            }

            data.Events.RemoveAll(e => e.ReceivedAt < eventsBefore);

            data.Gaps.RemoveAll(g => g.ReceivedAt < eventsBefore);
            foreach (var key in data.Counts.Keys.Where(k => k.Day < countsBefore).ToList())
            {
                data.Counts.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }

    private OrganisationData Of(string organisation)
    {
        if (!_byOrganisation.TryGetValue(organisation, out var data))
        {
            data = new OrganisationData();
            _byOrganisation[organisation] = data;
        }

        return data;
    }

    private sealed class OrganisationData
    {
        public HashSet<string> Ids { get; } = new(StringComparer.Ordinal);

        public List<ServerEvent> Events { get; } = [];

        public List<ServerEventGap> Gaps { get; } = [];

        public Dictionary<(DateOnly Day, string Outcome), int> Counts { get; } = [];

        public Dictionary<string, int> Dropped { get; } = new(StringComparer.Ordinal);
    }
}
