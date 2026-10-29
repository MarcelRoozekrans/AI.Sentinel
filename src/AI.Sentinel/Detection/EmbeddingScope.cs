using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>The generator and caches one pipeline uses to embed a scan.</summary>
/// <param name="generator">Embeds the scan's texts and, in the same scope, the examples.</param>
/// <param name="scanCache">Caches scan-text vectors for this generator.</param>
/// <param name="exampleCache">Caches example vectors for this generator, or <see langword="null"/> when none is configured.</param>
internal sealed class EmbeddingScope(
    IEmbeddingGenerator<string, Embedding<float>> generator,
    IEmbeddingCache scanCache,
    IEmbeddingCache? exampleCache)
{
    public IEmbeddingGenerator<string, Embedding<float>> Generator { get; } = generator;
    public IEmbeddingCache ScanCache { get; } = scanCache;
    public IEmbeddingCache? ExampleCache { get; } = exampleCache;
}
