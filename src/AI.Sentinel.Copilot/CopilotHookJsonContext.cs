using System.Text.Json.Serialization;
using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Copilot;

[JsonSerializable(typeof(CopilotHookInput))]
[JsonSerializable(typeof(HookOutput))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true)]
public sealed partial class CopilotHookJsonContext : JsonSerializerContext;
