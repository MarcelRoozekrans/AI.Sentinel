using System.Text.Json.Serialization;

namespace AI.Sentinel.Embeddings;

/// <summary>Source-generated so the CLIs stay trim- and AOT-safe.</summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(OpenAICompatibleEmbeddingGenerator.EmbeddingRequest))]
[JsonSerializable(typeof(OpenAICompatibleEmbeddingGenerator.EmbeddingResponse))]
internal sealed partial class EmbeddingJsonContext : JsonSerializerContext;
