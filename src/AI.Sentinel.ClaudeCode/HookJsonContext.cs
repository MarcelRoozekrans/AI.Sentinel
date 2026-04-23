using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode;

[JsonSerializable(typeof(HookInput))]
[JsonSerializable(typeof(HookOutput))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    UseStringEnumConverter = true)]
public sealed partial class HookJsonContext : JsonSerializerContext;
