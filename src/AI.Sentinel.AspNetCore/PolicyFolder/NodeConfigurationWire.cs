using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>The form of <c>nodes.json</c>, the node configuration in the policy folder.</summary>
internal sealed class NodeConfigurationWire
{
    [JsonPropertyName("organisation")]
    public string? Organisation { get; set; }

    /// <summary>Optional. A configuration version the filler states; the server counts its own publishes when it is absent.</summary>
    [JsonPropertyName("version")]
    public long? Version { get; set; }

    [JsonPropertyName("nodes")]
    public List<NodeWire>? Nodes { get; set; }

    /// <summary>Repository url or name to node id.</summary>
    [JsonPropertyName("repositories")]
    public Dictionary<string, string>? Repositories { get; set; }

    [JsonPropertyName("roles")]
    public List<RoleBindingWire>? Roles { get; set; }
}
