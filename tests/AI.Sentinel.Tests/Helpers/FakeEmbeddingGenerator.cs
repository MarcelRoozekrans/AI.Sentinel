using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// Deterministic embedding generator for unit tests. Uses character bigram
/// frequency vectors — identical strings score cosine 1.0, unrelated strings
/// score near 0. No API keys or network required.
/// </summary>
public sealed class FakeEmbeddingGenerator : IEmbeddingGenerator<string, Embedding<float>>
{
    public EmbeddingGeneratorMetadata Metadata { get; } = new("fake", null, null, 256);

    public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var embeddings = values.Select(v => new Embedding<float>(Embed(v))).ToList();
        return Task.FromResult(new GeneratedEmbeddings<Embedding<float>>(embeddings));
    }

    private static float[] Embed(string text)
    {
        var lower = text.ToLowerInvariant();
        var vec = new float[256];
        for (var i = 0; i < lower.Length - 1; i++)
        {
            var h = ((lower[i] & 0x7F) << 7 | (lower[i + 1] & 0x7F)) % 256;
            vec[h] += 1f;
        }
        var norm = MathF.Sqrt(vec.Sum(x => x * x));
        if (norm > 0f)
            return vec.Select(x => x / norm).ToArray();
        return vec;
    }

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
