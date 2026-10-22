using System.Text.Json.Serialization;

namespace AI.Sentinel.Copilot.Cli;

/// <summary>Source-generated serialization for <see cref="CopilotWireOutput"/>: camelCase, enums as strings.</summary>
[JsonSerializable(typeof(CopilotWireOutput))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true)]
internal sealed partial class CopilotWireJsonContext : JsonSerializerContext;
