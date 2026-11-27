namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>One Server-Sent Event: its name and its data. A heartbeat comment is an event with no name and no data.</summary>
internal sealed record SseMessage(string? Event, string? Data)
{
    public bool IsHeartbeat => Event is null && Data is null;
}
