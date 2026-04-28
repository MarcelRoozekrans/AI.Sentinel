using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detectors.Sdk;

/// <summary>
/// Deterministic character-bigram embedding generator for testing custom semantic detectors.
/// Identical input strings yield cosine similarity ~ 1.0; bigram-based vectors give predictable
/// behavior without API keys or network calls.
/// </summary>
/// <remarks>
/// <strong>For testing only.</strong> Uses character bigrams rather than real semantic embeddings —
/// the output vectors are NOT representative of actual model embeddings. Production code should use
/// a real <see cref="IEmbeddingGenerator{TInput, TEmbedding}"/> implementation (OpenAI, Cohere, etc.).
/// </remarks>
public sealed class FakeEmbeddingGenerator : IEmbeddingGenerator<string, Embedding<float>>
{
    /// <summary>Static metadata describing this generator (256-dimensional fake embeddings).</summary>
    public EmbeddingGeneratorMetadata Metadata { get; } = new("fake", null, null, 256);

    /// <inheritdoc />
    public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(values);
        var embeddings = new List<Embedding<float>>();
        foreach (var v in values)
        {
            embeddings.Add(new Embedding<float>(Embed(v)));
        }
        return Task.FromResult(new GeneratedEmbeddings<Embedding<float>>(embeddings));
    }

    private static float[] Embed(string text)
    {
        var lower = text.ToLowerInvariant();
        var vec = new float[256];
        var span = vec.AsSpan();
        for (var i = 0; i < lower.Length - 1; i++)
        {
            var h = ((lower[i] & 0x7F) << 7 | (lower[i + 1] & 0x7F)) % 256;
            span[h] += 1f;
        }
        var sumSq = 0f;
        foreach (var x in vec)
        {
            sumSq += x * x;
        }
        var norm = MathF.Sqrt(sumSq);
        if (norm > 0f)
        {
            // HLQ013 prefers foreach for read-only span iteration; in-place normalization
            // requires index-based mutation, so a manual for-loop is the right shape here.
#pragma warning disable HLQ013
            for (var i = 0; i < span.Length; i++)
            {
                span[i] /= norm;
            }
#pragma warning restore HLQ013
        }
        return vec;
    }

    /// <inheritdoc />
    public object? GetService(Type serviceType, object? key = null) => null;

    /// <inheritdoc />
    public void Dispose() { }
}
