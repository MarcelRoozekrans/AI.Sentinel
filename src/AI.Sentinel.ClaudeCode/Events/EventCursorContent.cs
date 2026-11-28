using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>The content of the cursor file.</summary>
internal sealed record EventCursorContent
{
    [JsonPropertyName("sequence")]
    public long Sequence { get; init; }

    /// <summary>The hash of the audit entry at <see cref="Sequence"/>, from the audit's hash chain. It tells a replaced audit file from
    /// the same one; <see langword="null"/> when no entry is known.</summary>
    [JsonPropertyName("hash")]
    public string? Hash { get; init; }

    /// <summary>The id of the audit file <see cref="Sequence"/> belongs to (#713); <see langword="null"/> in a cursor written before
    /// it was kept.</summary>
    [JsonPropertyName("file")]
    public string? File { get; init; }

    /// <summary>The ingest address the cursor is bound to (#723); <see langword="null"/> in a cursor written before it was kept, which
    /// binds it to no server.</summary>
    [JsonPropertyName("server")]
    public string? Server { get; init; }

    /// <summary>The organisation the cursor is bound to (#723).</summary>
    [JsonPropertyName("organisation")]
    public string? Organisation { get; init; }

    /// <summary>A gap the server has not taken yet; it goes out before the next entry.</summary>
    [JsonPropertyName("gap")]
    public EventGap? Gap { get; init; }
}
