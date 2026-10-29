using AI.Sentinel.Detection;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class ScanEmbedderTests
{
    private static EmbeddingScope Scope(IEmbeddingGenerator<string, Embedding<float>> gen, IEmbeddingCache cache) =>
        new(gen, cache, null);

    [Fact]
    public async Task Misses_are_embedded_in_one_batch_and_cached()
    {
        var gen = new YieldingEmbeddingGenerator();
        var cache = new InMemoryLruEmbeddingCache();
        string[] texts = ["a", "b", "c", "d", "e"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), texts, CancellationToken.None);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(5, gen.Batches[0].Count);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal(5, result.TotalCount);
        foreach (var t in texts)
        {
            Assert.True(cache.TryGet(t, out _));
            Assert.True(result.TryGet(t, out var v));
            Assert.False(v.IsEmpty);
        }
    }

    [Fact]
    public async Task Cached_texts_are_not_embedded()
    {
        var gen = new YieldingEmbeddingGenerator();
        var cache = new InMemoryLruEmbeddingCache();
        string[] texts = ["a", "b", "c", "d", "e"];
        foreach (var t in texts.Take(2))
        {
            var e = (await new FakeEmbeddingGenerator().GenerateAsync([t], cancellationToken: TestContext.Current.CancellationToken))[0];
            cache.Set(t, e);
        }

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), texts, CancellationToken.None);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(["c", "d", "e"], gen.Batches[0]);
        Assert.Equal(0, result.FailedCount);
        Assert.All(texts, t => Assert.True(result.TryGet(t, out _)));
    }

    [Fact]
    public async Task Batch_failure_retries_each_input_and_isolates_the_bad_one()
    {
        var gen = new YieldingEmbeddingGenerator(batch => batch.Contains("bad", StringComparer.Ordinal));
        string[] texts = ["a", "bad", "b", "c"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, CancellationToken.None);

        Assert.Equal(5, gen.Calls);
        Assert.Equal(1, result.FailedCount);
        Assert.False(result.TryGet("bad", out _));
        Assert.True(result.TryGet("a", out _));
        Assert.True(result.TryGet("b", out _));
        Assert.True(result.TryGet("c", out _));
    }

    [Fact]
    public async Task Outage_stops_after_first_two_single_failures()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true);
        string[] texts = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, CancellationToken.None);

        Assert.Equal(3, gen.Calls);
        Assert.Equal(10, result.FailedCount);
        Assert.IsType<HttpRequestException>(result.FirstFailure);
    }

    [Fact]
    public async Task Cut_off_does_not_apply_once_a_single_succeeded()
    {
        var gen = new YieldingEmbeddingGenerator(b => b.Count > 1 || b[0] is "x" or "y");
        string[] texts = ["a", "x", "y", "b"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, CancellationToken.None);

        Assert.Equal(5, gen.Calls);
        Assert.Equal(2, result.FailedCount);
        Assert.True(result.TryGet("a", out _));
        Assert.True(result.TryGet("b", out _));
    }

    [Fact]
    public async Task Single_missing_input_is_not_retried()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true);

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), ["a"], CancellationToken.None);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(1, result.FailedCount);
        Assert.IsType<HttpRequestException>(result.FirstFailure);
    }

    [Fact]
    public async Task Batch_count_mismatch_falls_back_to_single_calls()
    {
        var gen = new ShortBatchGenerator();
        string[] texts = ["a", "b", "c"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, CancellationToken.None);

        Assert.Equal([3, 1, 1, 1], gen.CallSizes);
        Assert.Equal(0, result.FailedCount);
        Assert.All(texts, t => Assert.True(result.TryGet(t, out _)));
    }

    [Fact]
    public async Task Single_input_count_mismatch_records_failure()
    {
        var gen = new EmptyResultGenerator();
        string[] texts = ["a", "b", "c"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, CancellationToken.None);

        // The batch, then two single failures trip the cut-off; the third input is never called.
        Assert.Equal(3, gen.Calls);
        Assert.Equal(result.TotalCount, result.FailedCount);
        Assert.NotNull(result.FirstFailure);
        Assert.All(texts, t => Assert.False(result.TryGet(t, out _)));
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), ["a", "b"], cts.Token));
    }

    private sealed class ShortBatchGenerator : IEmbeddingGenerator<string, Embedding<float>>
    {
        private readonly FakeEmbeddingGenerator _inner = new();
        public List<int> CallSizes { get; } = [];
        public EmbeddingGeneratorMetadata Metadata { get; } = new("short-batch", null, null, 256);

        public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default)
        {
            var list = values.ToList();
            CallSizes.Add(list.Count);
            var all = await _inner.GenerateAsync(list, options, cancellationToken);
            if (list.Count <= 1)
            {
                return all;
            }
            return new GeneratedEmbeddings<Embedding<float>>(all.Take(list.Count - 1).ToList());
        }

        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }

    private sealed class EmptyResultGenerator : IEmbeddingGenerator<string, Embedding<float>>
    {
        private int _calls;
        public int Calls => _calls;
        public EmbeddingGeneratorMetadata Metadata { get; } = new("empty", null, null, 256);

        public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(new GeneratedEmbeddings<Embedding<float>>());
        }

        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
