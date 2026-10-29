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

    /// <summary>Decides the scope a pipeline embeds with, from its own options and the default pipeline's scope.</summary>
    /// <remarks>A pipeline that sets its own generator gets its own caches too, never the default's, because vectors
    /// from different generators must not meet. One without a generator inherits the default's generator and, per
    /// cache, its own cache when set, otherwise the default's. Returns <see langword="null"/> when there is no
    /// generator anywhere, which leaves the semantic detectors inert.</remarks>
    internal static EmbeddingScope? Resolve(SentinelOptions options, EmbeddingScope? inherited)
    {
        if (options.EmbeddingGenerator is { } generator)
        {
            return new EmbeddingScope(
                generator,
                options.EmbeddingCache ?? new InMemoryLruEmbeddingCache(),
                options.ExampleEmbeddingCache);
        }

        return inherited is null
            ? null
            : new EmbeddingScope(
                inherited.Generator,
                options.EmbeddingCache ?? inherited.ScanCache,
                options.ExampleEmbeddingCache ?? inherited.ExampleCache);
    }
}
