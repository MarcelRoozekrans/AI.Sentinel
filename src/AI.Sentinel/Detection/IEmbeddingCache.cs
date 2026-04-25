using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>Cache for scan-time embedding vectors, keyed by input text.</summary>
/// <remarks>
/// Implementations must be thread-safe. The default implementation is
/// <see cref="InMemoryLruEmbeddingCache"/> (1 024-entry LRU, in-process only).
/// Supply a custom implementation via <see cref="SentinelOptions.EmbeddingCache"/>
/// to use a persistent store (Redis, SQLite, etc.).
/// </remarks>
public interface IEmbeddingCache
{
    /// <summary>Returns <see langword="true"/> and sets <paramref name="embedding"/> if the text is cached.</summary>
    bool TryGet(string text, out Embedding<float> embedding);
    /// <summary>Stores <paramref name="embedding"/> under <paramref name="text"/>. Overwrites any existing entry.</summary>
    void Set(string text, Embedding<float> embedding);
}
