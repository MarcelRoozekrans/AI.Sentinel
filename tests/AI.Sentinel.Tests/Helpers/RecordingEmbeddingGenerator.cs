using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// Wraps another generator and records every input of every call, in order, and the number of calls.
/// With <c>dropLast</c> it returns one vector fewer than it was asked for, to stand in for a provider
/// that batches, dedupes or drops inputs.
/// </summary>
public sealed class RecordingEmbeddingGenerator(
    IEmbeddingGenerator<string, Embedding<float>> inner,
    bool dropLast = false) : IEmbeddingGenerator<string, Embedding<float>>
{
    private readonly List<string> _inputs = [];

    /// <summary>Every input of every call, in call order.</summary>
    public IReadOnlyList<string> Inputs => _inputs;

    /// <summary>The number of <see cref="GenerateAsync"/> calls.</summary>
    public int Calls { get; private set; }

    public EmbeddingGeneratorMetadata Metadata { get; } = new("recording", null, null, null);

    public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var list = values.ToList();
        Calls++;
        _inputs.AddRange(list);

        var result = await inner.GenerateAsync(list, options, cancellationToken).ConfigureAwait(false);
        if (!dropLast || result.Count == 0)
        {
            return result;
        }

        var kept = new List<Embedding<float>>(result.Count - 1);
        for (var i = 0; i < result.Count - 1; i++)
        {
            kept.Add(result[i]);
        }
        return new GeneratedEmbeddings<Embedding<float>>(kept);
    }

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() => inner.Dispose();
}
