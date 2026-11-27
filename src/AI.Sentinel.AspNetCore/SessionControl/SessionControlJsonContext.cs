using System.Text.Json.Serialization;
using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.AspNetCore.SessionControl;

[JsonSerializable(typeof(PauseRequestWire))]
[JsonSerializable(typeof(PausedSession))]
[JsonSerializable(typeof(PauseListEntry[]))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class SessionControlJsonContext : JsonSerializerContext;
