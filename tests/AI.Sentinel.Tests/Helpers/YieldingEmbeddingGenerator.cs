using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// An embedding generator that completes asynchronously, as a real provider does, so tests that prove
/// concurrency or fan-out exercise the interleavings a synchronous fake hides. Embeds like
/// <see cref="FakeEmbeddingGenerator"/> after a one-millisecond delay, and records every call.
/// </summary>
/// <param name="failWhen">When it returns <see langword="true"/> for a call's inputs, that call throws
/// <see cref="HttpRequestException"/>.</param>
public sealed class YieldingEmbeddingGenerator(
    Func<IReadOnlyList<string>, bool>? failWhen = null) : IEmbeddingGenerator<string, Embedding<float>>
{
    private readonly FakeEmbeddingGenerator _inner = new();
#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _lock = new();
#else
    private readonly object _lock = new();
#endif
    private readonly List<IReadOnlyList<string>> _batches = [];
    private int _calls;

    /// <summary>When set, every call awaits it before embedding.</summary>
    public TaskCompletionSource? Gate { get; set; }

    /// <summary>The number of <see cref="GenerateAsync"/> calls.</summary>
    public int Calls { get { lock (_lock) { return _calls; } } }

    /// <summary>The inputs of each call, in call order.</summary>
    public IReadOnlyList<IReadOnlyList<string>> Batches { get { lock (_lock) { return [.. _batches]; } } }

    /// <summary>Every input of every call, in call order.</summary>
    public IReadOnlyList<string> Inputs { get { lock (_lock) { return [.. _batches.SelectMany(b => b)]; } } }

    public EmbeddingGeneratorMetadata Metadata { get; } = new("yielding", null, null, 256);

    public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var list = values.ToList();
        lock (_lock)
        {
            _calls++;
            _batches.Add(list);
        }

        if (Gate is { } gate)
        {
            await gate.Task.ConfigureAwait(false);
        }
        await Task.Delay(1, cancellationToken).ConfigureAwait(false);

        if (failWhen?.Invoke(list) == true)
        {
            throw new HttpRequestException("rejected");
        }

        return await _inner.GenerateAsync(list, options, cancellationToken).ConfigureAwait(false);
    }

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
