using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public interface IEmbeddingCache
{
    bool TryGet(string text, out Embedding<float> embedding);
    void Set(string text, Embedding<float> embedding);
}
