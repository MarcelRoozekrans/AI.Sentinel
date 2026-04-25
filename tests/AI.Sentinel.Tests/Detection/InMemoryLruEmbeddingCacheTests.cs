using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class InMemoryLruEmbeddingCacheTests
{
    [Fact]
    public void TryGet_Miss_ReturnsFalse()
    {
        var cache = new InMemoryLruEmbeddingCache();
        Assert.False(cache.TryGet("hello", out _));
    }

    [Fact]
    public void Set_ThenGet_ReturnsStoredVector()
    {
        var cache = new InMemoryLruEmbeddingCache();
        var emb = new Embedding<float>(new float[] { 1f, 0f });
        cache.Set("hello", emb);
        Assert.True(cache.TryGet("hello", out var result));
        Assert.Equal(emb.Vector.ToArray(), result.Vector.ToArray());
    }

    [Fact]
    public void Eviction_WhenCapacityExceeded_CacheRemainsWithinBounds()
    {
        var cache = new InMemoryLruEmbeddingCache(capacity: 4);
        for (var i = 0; i < 6; i++)
            cache.Set($"key{i}", new Embedding<float>(new float[] { i }));

        var hitCount = 0;
        for (var i = 0; i < 6; i++)
            if (cache.TryGet($"key{i}", out _)) hitCount++;

        Assert.True(hitCount <= 4);
    }
}
