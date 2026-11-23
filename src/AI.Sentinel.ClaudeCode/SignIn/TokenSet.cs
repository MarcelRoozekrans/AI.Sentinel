using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>The tokens of one sign-in. It never prints them: a token must not reach a log, the audit or an exception message.</summary>
internal sealed class TokenSet
{
    public TokenSet(string accessToken, string? refreshToken, DateTimeOffset expiresAt)
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
        ExpiresAt = expiresAt;
    }

    /// <summary>For the local channel, where a sign-in hands its tokens to the resident process.</summary>
    [JsonConstructor]
    public TokenSet(string accessToken, string? refreshToken, long expiresAtUnix)
        : this(accessToken, refreshToken, DateTimeOffset.FromUnixTimeSeconds(expiresAtUnix))
    {
    }

    [JsonPropertyName("access_token")]
    public string AccessToken { get; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; }

    [JsonIgnore]
    public DateTimeOffset ExpiresAt { get; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAtUnix => ExpiresAt.ToUnixTimeSeconds();

    public override string ToString() => "TokenSet [redacted]";
}
