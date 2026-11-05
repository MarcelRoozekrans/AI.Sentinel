using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// An embedding generator whose vectors a test chooses, so it can feed the code under test empty, zero-norm,
/// non-finite or wrong-length answers. Records every call.
/// </summary>
/// <param name="vectors">Returns the vector for an input text.</param>
public sealed class VectorEmbeddingGenerator(Func<string, float[]> vectors) : IEmbeddingGenerator<string, Embedding<float>>
{
#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _lock = new();
#else
    private readonly object _lock = new();
#endif
    private readonly List<IReadOnlyList<string>> _batches = [];

    /// <summary>Returns the vector for an input text. A test may switch the answers between calls.</summary>
    public Func<string, float[]> Vectors { get; set; } = vectors;

    /// <summary>When it returns <see langword="true"/> for a call's inputs, that call throws <see cref="HttpRequestException"/>.</summary>
    public Func<IReadOnlyList<string>, bool>? FailBatch { get; set; }

    /// <summary>The number of <see cref="GenerateAsync"/> calls.</summary>
    public int Calls { get { lock (_lock) { return _batches.Count; } } }

    /// <summary>The inputs of each call, in call order.</summary>
    public IReadOnlyList<IReadOnlyList<string>> Batches { get { lock (_lock) { return [.. _batches]; } } }

    public EmbeddingGeneratorMetadata Metadata { get; } = new("vector", null, null, 256);

    public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var list = values.ToList();
        lock (_lock)
        {
            _batches.Add(list);
        }

        if (FailBatch?.Invoke(list) == true)
        {
            throw new HttpRequestException("rejected");
        }

        return Task.FromResult(new GeneratedEmbeddings<Embedding<float>>(
            list.Select(t => new Embedding<float>(Vectors(t))).ToList()));
    }

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
