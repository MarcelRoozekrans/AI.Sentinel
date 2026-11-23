using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

[JsonSerializable(typeof(EventBatch))]
[JsonSerializable(typeof(EventCursorContent))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class EventsJsonContext : JsonSerializerContext;
