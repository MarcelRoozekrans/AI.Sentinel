using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

internal sealed class RoleBindingWire
{
    [JsonPropertyName("group")]
    public string? Group { get; set; }

    /// <summary><c>administrator</c> or <c>team_lead</c>.</summary>
    [JsonPropertyName("role")]
    public string? Role { get; set; }

    [JsonPropertyName("node")]
    public string? Node { get; set; }
}
