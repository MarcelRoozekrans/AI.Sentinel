using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>Entries the machine pruned before it could send them.</summary>
internal sealed class EventGap
{
    [JsonPropertyName("pruned")]
    public int Pruned { get; init; }

    [JsonPropertyName("node")]
    public string? Node { get; init; }
}
