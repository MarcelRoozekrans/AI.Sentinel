using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>The content of the cursor file.</summary>
internal sealed record EventCursorContent
{
    [JsonPropertyName("sequence")]
    public long Sequence { get; init; }

    /// <summary>The hash of the audit entry at <see cref="Sequence"/>, from the audit's hash chain. It tells a replaced audit file from
    /// the same one; <see langword="null"/> when no entry is known, as in a cursor written before it was kept.</summary>
    [JsonPropertyName("hash")]
    public string? Hash { get; init; }
}
