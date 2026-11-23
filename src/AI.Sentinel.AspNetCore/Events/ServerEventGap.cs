namespace AI.Sentinel.AspNetCore.Events;

/// <summary>A report that a developer's machine pruned events before it could send them.</summary>
internal sealed record ServerEventGap(string Organisation, string Developer, string? Node, int Pruned, DateTimeOffset ReceivedAt);
