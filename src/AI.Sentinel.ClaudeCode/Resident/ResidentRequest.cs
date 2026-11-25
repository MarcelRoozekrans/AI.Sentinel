using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>One request on the local channel: a JSON line, answered by one <see cref="ResidentResponse"/> line.</summary>
internal sealed record ResidentRequest
{
    /// <summary>One of <see cref="ResidentOps"/>.</summary>
    [JsonPropertyName("op")]
    public string Op { get; init; } = string.Empty;

    /// <summary>For <see cref="ResidentOps.Evaluate"/>: the policy folder.</summary>
    [JsonPropertyName("folder")]
    public string? Folder { get; init; }

    /// <summary>For <see cref="ResidentOps.Evaluate"/>: the version the hook read from the folder. A process that holds another
    /// version loads this one first.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    /// <summary>For <see cref="ResidentOps.Evaluate"/>: where the compiled forms of the policy are kept.</summary>
    [JsonPropertyName("cache_dir")]
    public string? CacheDirectory { get; init; }

    /// <summary>For <see cref="ResidentOps.Evaluate"/>: the policy input, as JSON text.</summary>
    [JsonPropertyName("input")]
    public string? Input { get; init; }
}
