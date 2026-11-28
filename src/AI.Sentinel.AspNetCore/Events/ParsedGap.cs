namespace AI.Sentinel.AspNetCore.Events;

/// <summary>A gap report: a count of entries, or <paramref name="Pruned"/> <see langword="null"/> when the machine does not know how
/// many. <paramref name="Id"/> makes a report that is sent again count once.</summary>
internal sealed record ParsedGap(int? Pruned, string? Node, string? Id, string? Cause);
