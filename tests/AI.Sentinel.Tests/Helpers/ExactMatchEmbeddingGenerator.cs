using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// Embeds each distinct text as its own one-hot vector, so a semantic detector fires only on a
/// verbatim copy of one of its examples and stays clean on everything else. Use it where a test needs
/// exactly one detector to fire: <see cref="FakeEmbeddingGenerator"/> scores two-character fragments,
/// and long English sentences look alike under it, so a single prompt fires dozens of detectors.
/// </summary>
/// <param name="recognised">Texts that are also recognised inside a larger text: a text that contains one embeds as
/// that text, so an example wrapped in a tool result or followed by other content still matches it exactly.</param>
public sealed class ExactMatchEmbeddingGenerator(params string[] recognised) : IEmbeddingGenerator<string, Embedding<float>>
{
    private const int Dimensions = 1 << 16;

    public EmbeddingGeneratorMetadata Metadata { get; } = new("exact-match", null, null, Dimensions);

    public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var embeddings = values.Select(v => new Embedding<float>(Embed(v))).ToList();
        return Task.FromResult(new GeneratedEmbeddings<Embedding<float>>(embeddings));
    }

    private float[] Embed(string text)
    {
        foreach (var known in recognised)
        {
            if (text.Contains(known, StringComparison.Ordinal))
            {
                text = known;
                break;
            }
        }

        // FNV-1a, so the slot is stable across processes, unlike string.GetHashCode.
        var hash = 2166136261u;
        foreach (var c in text)
        {
            hash = (hash ^ c) * 16777619u;
        }

        var vec = new float[Dimensions];
        vec[hash % Dimensions] = 1f;
        return vec;
    }

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
