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

    /// <summary>For <see cref="ResidentOps.SignIn"/>: the tokens. They never print, and are never written to a file.</summary>
    [JsonPropertyName("tokens")]
    public SignIn.TokenSet? Tokens { get; init; }

    /// <summary>For <see cref="ResidentOps.SignIn"/>: the issuer that issued the tokens. The resident takes them only for its own issuer.</summary>
    [JsonPropertyName("issuer")]
    public string? Issuer { get; init; }

    /// <summary>For <see cref="ResidentOps.SignIn"/>: the OIDC client the tokens were issued to.</summary>
    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; }

    /// <summary>For an evaluation: the session of the call. When a team lead has paused it the process answers deny, whatever the
    /// policy says.</summary>
    [JsonPropertyName("session")]
    public string? Session { get; init; }

    /// <summary>For <see cref="ResidentOps.EvaluateProfile"/>: the repository whose profile judges the call.</summary>
    [JsonPropertyName("repository")]
    public string? Repository { get; init; }
}
