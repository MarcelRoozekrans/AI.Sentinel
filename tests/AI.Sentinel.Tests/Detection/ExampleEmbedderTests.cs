using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests.Detection;

public class ExampleEmbedderTests
{
    private sealed class DroppingGenerator : IEmbeddingGenerator<string, Embedding<float>>
    {
        public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new GeneratedEmbeddings<Embedding<float>>([new Embedding<float>(new float[] { 1f })]));

        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }

    [Fact]
    public async Task EmbedAsync_ThrowsOnCountMismatch()
    {
        var cache = new InMemoryLruEmbeddingCache();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ExampleEmbedder.EmbedAsync(new DroppingGenerator(), cache, ["a", "b"], TestContext.Current.CancellationToken));
    }

    private sealed class VectorGenerator(Func<string, float[]> vectors) : IEmbeddingGenerator<string, Embedding<float>>
    {
        public int Calls { get; private set; }

        public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(new GeneratedEmbeddings<Embedding<float>>(values.Select(v => new Embedding<float>(vectors(v))).ToList()));
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }

    [Fact]
    public async Task EmbedAsync_NoCache_ThrowsOnCountMismatch()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ExampleEmbedder.EmbedAsync(new DroppingGenerator(), null, ["a", "b"], TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("empty", InvalidEmbeddingException.EmptyVector)]
    [InlineData("zero", InvalidEmbeddingException.InvalidVector)]
    [InlineData("nan", InvalidEmbeddingException.InvalidVector)]
    [InlineData("infinite", InvalidEmbeddingException.InvalidVector)]
    public async Task EmbedAsync_InvalidVector_ThrowsAndCachesNothing(string shape, string kind)
    {
        float[] bad = shape switch
        {
            "empty" => [],
            "zero" => [0f, 0f],
            "nan" => [float.NaN, 1f],
            _ => [float.NegativeInfinity, 1f],
        };
        var cache = new InMemoryLruEmbeddingCache();
        var generator = new VectorGenerator(t => string.Equals(t, "b", StringComparison.Ordinal) ? bad : [1f, 0f]);

        var ex = await Assert.ThrowsAsync<InvalidEmbeddingException>(() =>
            ExampleEmbedder.EmbedAsync(generator, cache, ["a", "b"], TestContext.Current.CancellationToken));

        Assert.Equal(kind, ex.Kind);
        Assert.False(cache.TryGet("a", out _));
        Assert.False(cache.TryGet("b", out _));
    }

    [Fact]
    public async Task EmbedAsync_NoCache_InvalidVector_Throws()
    {
        var generator = new VectorGenerator(_ => [0f, 0f]);

        var ex = await Assert.ThrowsAsync<InvalidEmbeddingException>(() =>
            ExampleEmbedder.EmbedAsync(generator, null, ["a"], TestContext.Current.CancellationToken));

        Assert.Equal(InvalidEmbeddingException.InvalidVector, ex.Kind);
    }

    [Fact]
    public async Task EmbedAsync_MixedLengthsInResponse_ThrowsAndCachesNothing()
    {
        var cache = new InMemoryLruEmbeddingCache();
        var generator = new VectorGenerator(t => string.Equals(t, "b", StringComparison.Ordinal) ? [1f, 0f, 0f] : [1f, 0f]);

        var ex = await Assert.ThrowsAsync<InvalidEmbeddingException>(() =>
            ExampleEmbedder.EmbedAsync(generator, cache, ["a", "b"], TestContext.Current.CancellationToken));

        Assert.Equal(InvalidEmbeddingException.DimensionMismatch, ex.Kind);
        Assert.False(cache.TryGet("a", out _));
    }

    [Fact]
    public async Task EmbedAsync_FreshLengthDiffersFromCached_ThrowsAndCachesNothing()
    {
        var cache = new InMemoryLruEmbeddingCache();
        cache.Set("a", new Embedding<float>(new[] { 1f, 0f }));
        var generator = new VectorGenerator(_ => [1f, 0f, 0f]);

        var ex = await Assert.ThrowsAsync<InvalidEmbeddingException>(() =>
            ExampleEmbedder.EmbedAsync(generator, cache, ["a", "b"], TestContext.Current.CancellationToken));

        Assert.Equal(InvalidEmbeddingException.DimensionMismatch, ex.Kind);
        Assert.False(cache.TryGet("b", out _));
    }

    [Fact]
    public async Task EmbedAsync_InvalidCachedVector_IsEmbeddedAgain()
    {
        var cache = new InMemoryLruEmbeddingCache();
        cache.Set("a", new Embedding<float>(new[] { 0f, 0f }));
        var generator = new VectorGenerator(_ => [1f, 0f]);

        var vectors = await ExampleEmbedder.EmbedAsync(generator, cache, ["a"], TestContext.Current.CancellationToken);

        Assert.Equal(1, generator.Calls);
        Assert.Equal([1f, 0f], vectors[0].ToArray());
        Assert.True(cache.TryGet("a", out var fixedUp));
        Assert.Equal([1f, 0f], fixedUp.Vector.ToArray());
    }
}
