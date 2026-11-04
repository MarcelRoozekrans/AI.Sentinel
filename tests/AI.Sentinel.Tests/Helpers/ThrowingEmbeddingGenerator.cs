using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>An embedding generator whose every call throws <see cref="InvalidOperationException"/>, for the paths
/// that must fail closed or degrade when embedding fails.</summary>
public sealed class ThrowingEmbeddingGenerator : IEmbeddingGenerator<string, Embedding<float>>
{
    public EmbeddingGeneratorMetadata Metadata { get; } = new("throwing", null, null, 256);

    public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
        => throw new InvalidOperationException("intentional test failure");

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
