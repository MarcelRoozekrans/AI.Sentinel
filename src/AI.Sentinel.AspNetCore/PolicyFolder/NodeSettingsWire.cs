using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

internal sealed class NodeSettingsWire
{
    [JsonPropertyName("fail_mode")]
    public string? FailMode { get; set; }

    [JsonPropertyName("profile_lifetime_hours")]
    public int? ProfileLifetimeHours { get; set; }

    [JsonPropertyName("detailed_logging")]
    public bool? DetailedLogging { get; set; }

    [JsonPropertyName("names")]
    public NodeNamesWire? Names { get; set; }

    [JsonPropertyName("severity_defaults")]
    public Dictionary<string, string>? SeverityDefaults { get; set; }
}
