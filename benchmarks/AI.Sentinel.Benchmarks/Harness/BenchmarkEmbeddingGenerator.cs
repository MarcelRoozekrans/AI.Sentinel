using Microsoft.Extensions.AI;

namespace AI.Sentinel.Benchmarks.Harness;

/// <summary>
/// Deterministic embedding generator for benchmarks.
/// <paramref name="latencyMs"/> simulates API round-trip latency (0 = in-process only).
/// </summary>
internal sealed class BenchmarkEmbeddingGenerator(int latencyMs = 0)
    : IEmbeddingGenerator<string, Embedding<float>>
{
    public EmbeddingGeneratorMetadata Metadata { get; } = new("benchmark", null, null, 256);

    public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (latencyMs > 0)
            await Task.Delay(latencyMs, cancellationToken).ConfigureAwait(false);

        var embeddings = values.Select(v => new Embedding<float>(Embed(v))).ToList();
        return new GeneratedEmbeddings<Embedding<float>>(embeddings);
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
            for (var i = 0; i < vec.Length; i++) vec[i] /= norm;
        return vec;
    }

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
