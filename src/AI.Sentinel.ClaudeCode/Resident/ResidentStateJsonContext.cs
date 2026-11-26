using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Source generated serialization of the state folder files: no runtime reflection, safe under Native AOT.</summary>
[JsonSerializable(typeof(PausedSession[]))]
[JsonSerializable(typeof(PinnedKeysFileContent))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class ResidentStateJsonContext : JsonSerializerContext;
