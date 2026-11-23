using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The answer to a <see cref="ResidentRequest"/>.</summary>
internal sealed record ResidentResponse
{
    /// <summary>True when the request was understood and carried out.</summary>
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    /// <summary>The process id of the resident process.</summary>
    [JsonPropertyName("pid")]
    public int Pid { get; init; }

    /// <summary>Why the request failed; never a secret.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }
}
