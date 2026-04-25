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
    public void Constructor_ZeroCapacity_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryLruEmbeddingCache(0));
    }

    [Fact]
    public void Constructor_NegativeCapacity_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryLruEmbeddingCache(-1));
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

    [Fact]
    public void Eviction_LruOrdering_LeastRecentlyUsedEvicted()
    {
        var cache = new InMemoryLruEmbeddingCache(capacity: 2);
        var e = new Embedding<float>(new float[] { 1f });

        cache.Set("A", e);  // tick=1
        cache.Set("B", e);  // tick=2
        cache.TryGet("A", out _);  // tick=3 — A is now most recent, B is LRU

        // fill past capacity → eviction must run
        cache.Set("C", e);  // capacity=2, new key → evict half (LRU = B)

        // B should be evicted; A should survive
        Assert.True(cache.TryGet("A", out _), "A was most recently used and should survive eviction");
        Assert.False(cache.TryGet("B", out _), "B was least recently used and should have been evicted");
    }

    [Fact]
    public void Set_ExistingKeyAtCapacity_DoesNotEvict()
    {
        var cache = new InMemoryLruEmbeddingCache(capacity: 2);
        var e = new Embedding<float>(new float[] { 1f });

        cache.Set("A", e);
        cache.Set("B", e);
        // cache is now at capacity; overwriting "A" must NOT evict anything
        cache.Set("A", new Embedding<float>(new float[] { 2f }));

        Assert.True(cache.TryGet("A", out _), "A should still be present after update");
        Assert.True(cache.TryGet("B", out _), "B should not have been evicted");
    }
}
