using System.Text.Json.Serialization;

namespace AI.Sentinel.Review;

/// <summary>Source-generated so the CLIs stay trim- and AOT-safe.</summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(OpenAICompatibleChatClient.CompletionRequest))]
[JsonSerializable(typeof(OpenAICompatibleChatClient.CompletionResponse))]
internal sealed partial class ReviewJsonContext : JsonSerializerContext;
