using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>The content of the cursor file.</summary>
internal sealed record EventCursorContent
{
    [JsonPropertyName("sequence")]
    public long Sequence { get; init; }
}
