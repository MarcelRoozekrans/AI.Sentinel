namespace AI.Sentinel.AspNetCore.Events;

/// <summary>A report that a developer's machine has events the server will never get: pruned before they were sent, skipped after a
/// server change, or in an audit file that was replaced. <paramref name="Pruned"/> is <see langword="null"/> when the machine does not
/// know how many. A report with an <paramref name="Id"/> is stored once per developer, so a batch that is sent again adds no second gap.</summary>
internal sealed record ServerEventGap(
    string Organisation, string Developer, string? Node, int? Pruned, DateTimeOffset ReceivedAt, string? Id = null, string? Cause = null);
