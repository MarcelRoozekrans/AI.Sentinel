using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.SessionControl;

/// <summary>The body of a pause request. A pause names a session; the repository says whose node decides who may pause it.</summary>
internal sealed record PauseRequestWire
{
    [JsonPropertyName("repository")]
    public string? Repository { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("until")]
    public DateTimeOffset? Until { get; init; }
}
