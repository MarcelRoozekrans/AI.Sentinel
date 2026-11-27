using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>The body of one request to the ingest endpoint.</summary>
internal sealed class EventBatch
{
    [JsonPropertyName("organisation")]
    public required string Organisation { get; init; }

    [JsonPropertyName("events")]
    public required List<ForwardedEvent> Events { get; init; }

    [JsonPropertyName("gap")]
    public EventGap? Gap { get; init; }
}
