using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

internal sealed class NodeWire
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary><c>organisation</c> or <c>team</c>.</summary>
    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    [JsonPropertyName("settings")]
    public NodeSettingsWire? Settings { get; set; }
}
