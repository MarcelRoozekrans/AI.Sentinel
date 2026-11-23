using System.Text.Json;
using System.Text.Json.Serialization;

namespace RegoAot;

/// <summary>One sample tool call and the outcome the policy bundles must give for it.</summary>
internal sealed class CaseFile
{
    [JsonPropertyName("expected")]
    public string Expected { get; set; } = "";

    [JsonPropertyName("expected_reasons")]
    public List<string> ExpectedReasons { get; set; } = [];

    [JsonPropertyName("input")]
    public JsonElement Input { get; set; }
}

/// <summary>The decision the entrypoint sentinel/decision returns.</summary>
internal sealed class DecisionDto
{
    [JsonPropertyName("outcome")]
    public string Outcome { get; set; } = "";

    [JsonPropertyName("reasons")]
    public List<string> Reasons { get; set; } = [];
}

[JsonSerializable(typeof(CaseFile))]
[JsonSerializable(typeof(DecisionDto))]
internal sealed partial class SpikeJson : JsonSerializerContext;
