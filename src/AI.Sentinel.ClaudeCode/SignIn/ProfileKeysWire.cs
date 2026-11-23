using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>The contract of the server's endpoint that hands out the public keys to pin (#671). The server side is #664.</summary>
internal sealed record ProfileKeysWire
{
    [JsonPropertyName("organisation")]
    public string? Organisation { get; init; }

    [JsonPropertyName("keys")]
    public List<string>? Keys { get; init; }
}
