using System.Text.Json.Serialization;

namespace AI.Sentinel.Profiles;

/// <summary>
/// What the organisation's server tells one PC to enforce (ADR-233). The server signs it, see
/// <see cref="ProfileSigner"/>; the plugin only enforces a profile that <see cref="ProfileVerifier"/> accepts.
/// </summary>
internal sealed record PolicyProfile
{
    /// <summary>The organisation the profile was issued for.</summary>
    [JsonPropertyName("organisation")]
    public required string Organisation { get; init; }

    /// <summary>The repository the profile applies to.</summary>
    [JsonPropertyName("repository")]
    public required string Repository { get; init; }

    /// <summary>The node (PC) the profile was issued to.</summary>
    [JsonPropertyName("node")]
    public required string Node { get; init; }

    /// <summary>Version of the organisation's configuration this profile was built from.</summary>
    [JsonPropertyName("configuration_version")]
    public required long ConfigurationVersion { get; init; }

    /// <summary>Hash of <see cref="Module"/>, so the PC can tell whether its cached module is current.</summary>
    [JsonPropertyName("module_hash")]
    public required string ModuleHash { get; init; }

    /// <summary>The policy module text.</summary>
    [JsonPropertyName("module")]
    public required string Module { get; init; }

    /// <summary>One of <see cref="ProfileFailModes"/>.</summary>
    [JsonPropertyName("fail_mode")]
    public required string FailMode { get; init; }

    /// <summary>Default action per severity name.</summary>
    [JsonPropertyName("severity_defaults")]
    public required IReadOnlyDictionary<string, string> SeverityDefaults { get; init; }

    /// <summary>Logging switches by name.</summary>
    [JsonPropertyName("logging")]
    public required IReadOnlyDictionary<string, bool> LoggingSwitches { get; init; }

    /// <summary>When the server issued the profile. Whole seconds, UTC.</summary>
    [JsonPropertyName("issued_at")]
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>When the profile stops being usable, also offline. Whole seconds, UTC.</summary>
    [JsonPropertyName("expires_at")]
    public required DateTimeOffset ExpiresAt { get; init; }
}
