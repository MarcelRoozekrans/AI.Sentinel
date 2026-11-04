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
}
