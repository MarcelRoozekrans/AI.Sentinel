using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>The answer of the keys endpoint: what the sign-in of the hook adapters reads.</summary>
internal sealed class ProfileKeysResponse
{
    [JsonPropertyName("organisation")]
    public required string Organisation { get; init; }

    [JsonPropertyName("keys")]
    public required List<string> Keys { get; init; }
}
