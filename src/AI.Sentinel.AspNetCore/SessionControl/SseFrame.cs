namespace AI.Sentinel.AspNetCore.SessionControl;

/// <summary>One event of the stream, ready to write.</summary>
internal sealed record SseFrame(string Event, string Data);
