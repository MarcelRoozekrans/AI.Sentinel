namespace AI.Sentinel.AspNetCore.Events;

/// <summary>An event as a read shows it: under the node it may be shown under, with or without the code of the developer.</summary>
internal sealed record ShownEvent(ServerEvent Event, string? Node, bool ShowDeveloper);
