using System.Text.Json.Serialization;

namespace AI.Sentinel.Codex.Cli;

/// <summary>Source-generated serialization for <see cref="CodexWireOutput"/>: camelCase, null members left out.</summary>
[JsonSerializable(typeof(CodexWireOutput))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class CodexWireJsonContext : JsonSerializerContext;
