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
        string[] texts = ["aa", "bb", "cc", "dd", "ee"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), texts, expectedDimension: null, CancellationToken.None);

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
        string[] texts = ["aa", "bb", "cc", "dd", "ee"];
        foreach (var t in texts.Take(2))
        {
            var e = (await new FakeEmbeddingGenerator().GenerateAsync([t], cancellationToken: TestContext.Current.CancellationToken))[0];
            cache.Set(t, e);
        }

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), texts, expectedDimension: null, CancellationToken.None);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(["cc", "dd", "ee"], gen.Batches[0]);
        Assert.Equal(0, result.FailedCount);
        Assert.All(texts, t => Assert.True(result.TryGet(t, out _)));
    }

    [Fact]
    public async Task Batch_failure_retries_each_input_and_isolates_the_bad_one()
    {
        var gen = new YieldingEmbeddingGenerator(batch => batch.Contains("bad", StringComparer.Ordinal));
        string[] texts = ["aa", "bad", "bb", "cc"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, CancellationToken.None);

        Assert.Equal(5, gen.Calls);
        Assert.Equal(1, result.FailedCount);
        Assert.False(result.TryGet("bad", out _));
        Assert.True(result.TryGet("aa", out _));
        Assert.True(result.TryGet("bb", out _));
        Assert.True(result.TryGet("cc", out _));
    }

    [Fact]
    public async Task Outage_stops_after_first_two_single_failures()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true);
        string[] texts = ["aa", "bb", "cc", "dd", "ee", "f", "g", "h", "i", "j"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, CancellationToken.None);

        Assert.Equal(3, gen.Calls);
        Assert.Equal(10, result.FailedCount);
        Assert.IsType<HttpRequestException>(result.FirstFailure);
    }

    [Fact]
    public async Task Cut_off_does_not_apply_once_a_single_succeeded()
    {
        var gen = new YieldingEmbeddingGenerator(b => b.Count > 1 || b[0] is "xx" or "yy");
        string[] texts = ["aa", "xx", "yy", "bb"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, CancellationToken.None);

        Assert.Equal(5, gen.Calls);
        Assert.Equal(2, result.FailedCount);
        Assert.True(result.TryGet("aa", out _));
        Assert.True(result.TryGet("bb", out _));
    }

    [Fact]
    public async Task Single_missing_input_is_not_retried()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true);

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), ["a"], expectedDimension: null, CancellationToken.None);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(1, result.FailedCount);
        Assert.IsType<HttpRequestException>(result.FirstFailure);
    }

    [Fact]
    public async Task Batch_count_mismatch_falls_back_to_single_calls()
    {
        var gen = new ShortBatchGenerator();
        string[] texts = ["aa", "bb", "cc"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, CancellationToken.None);

        Assert.Equal([3, 1, 1, 1], gen.CallSizes);
        Assert.Equal(0, result.FailedCount);
        Assert.All(texts, t => Assert.True(result.TryGet(t, out _)));
    }

    [Fact]
    public async Task Single_input_count_mismatch_records_failure()
    {
        var gen = new EmptyResultGenerator();
        string[] texts = ["a", "b", "c"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, CancellationToken.None);

        // The batch, then two single failures trip the cut-off; the third input is never called.
        Assert.Equal(3, gen.Calls);
        Assert.Equal(result.TotalCount, result.FailedCount);
        Assert.NotNull(result.FirstFailure);
        Assert.All(texts, t => Assert.False(result.TryGet(t, out _)));
    }

    [Fact]
    public async Task Failure_messages_never_contain_an_input_text()
    {
        var gen = new EmptyResultGenerator();
        string[] texts = ["secret-alpha", "secret-beta", "secret-gamma"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, CancellationToken.None);

        Assert.NotNull(result.FirstFailure);
        Assert.All(texts, t => Assert.DoesNotContain(t, result.FirstFailure.Message, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Batch_timeout_on_a_live_token_fails_every_input_without_retries()
    {
        // HttpClient reports its timeout as a TaskCanceledException while the caller's token is not cancelled.
        var gen = new YieldingEmbeddingGenerator(_ => true) { Failure = _ => new TaskCanceledException("timed out") };
        string[] texts = ["a", "b", "c"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, TestContext.Current.CancellationToken);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(3, result.FailedCount);
        Assert.IsType<TaskCanceledException>(result.FirstFailure);
        Assert.All(texts, t => Assert.False(result.TryGet(t, out _)));
    }

    [Fact]
    public async Task Single_input_timeout_on_a_live_token_counts_as_a_failure()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true)
        {
            Failure = batch => batch.Count > 1 ? new HttpRequestException("rejected") : new TaskCanceledException("timed out"),
        };
        string[] texts = ["a", "b", "c"];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: null, TestContext.Current.CancellationToken);

        // The batch, then two single failures trip the cut-off.
        Assert.Equal(3, gen.Calls);
        Assert.Equal(3, result.FailedCount);
        Assert.IsType<HttpRequestException>(result.FirstFailure);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Cancellation_wins_over_a_non_cancellation_exception(int cancelOnCall)
    {
        // Call 1 is the batch, call 2 the first single-input retry.
        using var cts = new CancellationTokenSource();
        var gen = new CancelThenThrowGenerator(cts, cancelOnCall);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), ["a", "b", "c"], expectedDimension: null, cts.Token));

        Assert.Equal(cancelOnCall, gen.Calls);
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), ["a", "b"], expectedDimension: null, cts.Token));
    }

    private static readonly float[] Good = [1f, 0f, 0f];

    public static TheoryData<float[], string> UnusableFresh => new()
    {
        { [], InvalidEmbeddingException.EmptyVector },
        { [0f, 0f, 0f], InvalidEmbeddingException.InvalidVector },
        { [float.NaN, 1f, 0f], InvalidEmbeddingException.InvalidVector },
        { [1f, 0f], InvalidEmbeddingException.DimensionMismatch },
    };

    [Theory]
    [MemberData(nameof(UnusableFresh))]
    public async Task Unusable_fresh_vector_is_not_cached_and_counts_as_failed(float[] vector, string expectedKind)
    {
        var gen = new VectorEmbeddingGenerator(_ => vector);
        var cache = new InMemoryLruEmbeddingCache();

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), ["x"], expectedDimension: 3, TestContext.Current.CancellationToken);

        Assert.Equal(1, result.FailedCount);
        Assert.False(result.TryGet("x", out _));
        Assert.False(cache.TryGet("x", out _));
        Assert.Equal(expectedKind, Assert.IsType<InvalidEmbeddingException>(result.FirstFailure).Kind);
    }

    [Fact]
    public async Task Invalid_vector_in_a_batch_fails_only_that_text()
    {
        var gen = new VectorEmbeddingGenerator(t => t is "bad" ? [0f, 0f, 0f] : Good);
        var cache = new InMemoryLruEmbeddingCache();

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), ["a", "bad", "b"], expectedDimension: 3, TestContext.Current.CancellationToken);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(1, result.FailedCount);
        Assert.False(result.TryGet("bad", out _));
        Assert.False(cache.TryGet("bad", out _));
        Assert.All(new[] { "a", "b" }, t =>
        {
            Assert.True(result.TryGet(t, out _));
            Assert.True(cache.TryGet(t, out _));
        });
    }

    [Fact]
    public async Task Invalid_vectors_do_not_count_as_an_outage()
    {
        var gen = new VectorEmbeddingGenerator(t => t is "t0" or "t1" ? [0f, 0f, 0f] : Good);
        string[] texts = [.. Enumerable.Range(0, 10).Select(i => $"t{i}")];

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), texts, expectedDimension: 3, TestContext.Current.CancellationToken);

        Assert.Equal(1, gen.Calls);
        Assert.Equal(2, result.FailedCount);
    }

    [Fact]
    public async Task Invalid_cached_hit_is_re_embedded()
    {
        var gen = new VectorEmbeddingGenerator(_ => Good);
        var cache = new InMemoryLruEmbeddingCache();
        cache.Set("a", new Embedding<float>(new float[] { 0f, 0f, 0f }));

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), ["a"], expectedDimension: 3, TestContext.Current.CancellationToken);

        Assert.Equal(["a"], gen.Batches[0]);
        Assert.Equal(0, result.FailedCount);
        Assert.True(cache.TryGet("a", out var stored));
        Assert.Equal(Good, stored.Vector.ToArray());
    }

    [Fact]
    public async Task Wrong_length_cached_hit_is_re_embedded()
    {
        var gen = new VectorEmbeddingGenerator(_ => Good);
        var cache = new InMemoryLruEmbeddingCache();
        cache.Set("a", new Embedding<float>(new float[] { 1f, 0f }));

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), ["a"], expectedDimension: 3, TestContext.Current.CancellationToken);

        Assert.Equal(["a"], gen.Batches[0]);
        Assert.Equal(0, result.FailedCount);
        Assert.True(cache.TryGet("a", out var stored));
        Assert.Equal(Good, stored.Vector.ToArray());
    }

    [Fact]
    public async Task Without_expected_dimension_the_first_usable_vector_sets_it()
    {
        var gen = new VectorEmbeddingGenerator(t => t is "b" ? [1f, 0f] : Good);

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, new InMemoryLruEmbeddingCache()), ["a", "b", "c"], expectedDimension: null, TestContext.Current.CancellationToken);

        Assert.Equal(1, result.FailedCount);
        Assert.False(result.TryGet("b", out _));
        Assert.True(result.TryGet("a", out _));
        Assert.True(result.TryGet("c", out _));
        Assert.Equal(InvalidEmbeddingException.DimensionMismatch, Assert.IsType<InvalidEmbeddingException>(result.FirstFailure).Kind);
    }

    [Fact]
    public async Task Unusable_single_retry_vector_counts_as_failed()
    {
        var gen = new VectorEmbeddingGenerator(t => t is "bad" ? [0f, 0f, 0f] : Good)
        {
            FailBatch = batch => batch.Count > 1,
        };
        var cache = new InMemoryLruEmbeddingCache();

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), ["a", "bad", "b"], expectedDimension: 3, TestContext.Current.CancellationToken);

        Assert.Equal(1, result.FailedCount);
        Assert.False(result.TryGet("bad", out _));
        Assert.False(cache.TryGet("bad", out _));
        Assert.True(result.TryGet("a", out _));
        Assert.True(result.TryGet("b", out _));
        Assert.IsType<HttpRequestException>(result.FirstFailure);
    }

    [Fact]
    public async Task Unusable_retry_vectors_do_not_trip_the_outage_cut_off()
    {
        // The batch throws; the first two singles answer with zero vectors, which are bad answers, not an outage.
        var gen = new VectorEmbeddingGenerator(t => t is "good" ? Good : [0f, 0f, 0f])
        {
            FailBatch = batch => batch.Count > 1,
        };
        var cache = new InMemoryLruEmbeddingCache();

        var result = await ScanEmbedder.EmbedAsync(Scope(gen, cache), ["bad1", "bad2", "good"], expectedDimension: 3, TestContext.Current.CancellationToken);

        Assert.Equal(4, gen.Calls);
        Assert.Equal(2, result.FailedCount);
        Assert.True(result.TryGet("good", out _));
        Assert.True(cache.TryGet("good", out _));
        Assert.IsType<HttpRequestException>(result.FirstFailure);
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

    private sealed class CancelThenThrowGenerator(CancellationTokenSource cts, int cancelOnCall)
        : IEmbeddingGenerator<string, Embedding<float>>
    {
        private int _calls;
        public int Calls => _calls;
        public EmbeddingGeneratorMetadata Metadata { get; } = new("cancel-then-throw", null, null, 256);

        public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default)
        {
            var call = Interlocked.Increment(ref _calls);
            if (call == cancelOnCall)
            {
                await cts.CancelAsync();
            }
            throw new HttpRequestException("rejected");
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
