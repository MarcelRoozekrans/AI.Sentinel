using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Source generated serialization of the event stream: no runtime reflection, safe under Native AOT.</summary>
[JsonSerializable(typeof(SessionSnapshot))]
[JsonSerializable(typeof(PausedSession))]
[JsonSerializable(typeof(ReleasedSession))]
[JsonSerializable(typeof(ConfigurationAnnounced))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class SessionEventJsonContext : JsonSerializerContext;
