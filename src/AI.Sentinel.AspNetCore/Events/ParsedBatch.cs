namespace AI.Sentinel.AspNetCore.Events;

internal sealed record ParsedBatch(
    string Organisation, IReadOnlyList<ParsedEvent> Events, Dictionary<string, int> Dropped, int Rejected, ParsedGap? Gap);
