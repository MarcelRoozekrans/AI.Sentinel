using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>The names setting of a node: whether the events endpoints show a code per developer, and the approval it rests on.</summary>
internal sealed class NodeNamesWire
{
    [JsonPropertyName("show")]
    public bool? Show { get; set; }

    /// <summary>The reference of the approval for showing names, such as a DPIA. Required when <c>show</c> is true.</summary>
    [JsonPropertyName("approval_reference")]
    public string? ApprovalReference { get; set; }
}
