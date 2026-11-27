namespace AI.Sentinel.AspNetCore.Events;

/// <summary>A gap as a read shows it.</summary>
internal sealed record ShownGap(ServerEventGap Gap, string? Node, bool ShowDeveloper);
