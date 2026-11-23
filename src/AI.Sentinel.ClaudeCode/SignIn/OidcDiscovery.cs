using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.SignIn;

internal sealed record OidcDiscovery
{
    [JsonPropertyName("device_authorization_endpoint")]
    public string? DeviceAuthorizationEndpoint { get; init; }

    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; init; }
}
