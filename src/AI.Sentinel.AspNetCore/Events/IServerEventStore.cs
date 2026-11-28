namespace AI.Sentinel.AspNetCore.Events;

/// <summary>Keeps what the ingest endpoint accepted, per organisation. Holds codes, never identities: the key for the codes is not
/// reachable from a store.</summary>
internal interface IServerEventStore
{
    /// <summary>Stores <paramref name="serverEvent"/> and counts it in the daily counts, unless its id was stored for the organisation
    /// before. Returns <see langword="false"/> for a duplicate.</summary>
    ValueTask<bool> AddAsync(ServerEvent serverEvent, CancellationToken ct);

    /// <summary>Stores a gap report. A report with an id that this developer sent before is not stored again.</summary>
    ValueTask AddGapAsync(ServerEventGap gap, CancellationToken ct);

    /// <summary>Adds to the count of received fields that are not on the allowlist, by field name.</summary>
    ValueTask AddDroppedAsync(string organisation, IReadOnlyDictionary<string, int> names, CancellationToken ct);

    ValueTask<IReadOnlyList<ServerEvent>> ReadEventsAsync(string organisation, CancellationToken ct);

    ValueTask<IReadOnlyList<ServerEventGap>> ReadGapsAsync(string organisation, CancellationToken ct);

    ValueTask<IReadOnlyList<DailyCount>> ReadDailyCountsAsync(string organisation, CancellationToken ct);

    ValueTask<IReadOnlyDictionary<string, int>> ReadDroppedAsync(string organisation, CancellationToken ct);

    /// <summary>Deletes events and gaps received before <paramref name="eventsBefore"/> and daily counts of days before
    /// <paramref name="countsBefore"/>.</summary>
    ValueTask PruneAsync(string organisation, DateTimeOffset eventsBefore, DateOnly countsBefore, CancellationToken ct);
}
