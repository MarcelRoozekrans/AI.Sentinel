using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Cli;

/// <summary>Source-generated serialization for <see cref="ClaudeCodeWireOutput"/>: camelCase, null members left out.</summary>
[JsonSerializable(typeof(ClaudeCodeWireOutput))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class ClaudeCodeWireJsonContext : JsonSerializerContext;
