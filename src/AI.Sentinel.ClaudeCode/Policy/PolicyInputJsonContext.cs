using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>Source generated serialization of <see cref="PolicyInput"/>: no runtime reflection, safe under Native AOT.</summary>
[JsonSerializable(typeof(PolicyInput))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class PolicyInputJsonContext : JsonSerializerContext;
