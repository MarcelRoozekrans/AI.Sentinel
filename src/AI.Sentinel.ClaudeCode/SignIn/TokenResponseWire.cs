using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.SignIn;

internal sealed record TokenResponseWire
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; init; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    [JsonPropertyName("error")]
    public string? Error { get; init; }
}
