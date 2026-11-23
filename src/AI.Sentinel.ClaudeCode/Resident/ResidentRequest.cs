using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>One request on the local channel: a JSON line, answered by one <see cref="ResidentResponse"/> line.</summary>
internal sealed record ResidentRequest
{
    /// <summary>One of <see cref="ResidentOps"/>.</summary>
    [JsonPropertyName("op")]
    public string Op { get; init; } = string.Empty;
}
