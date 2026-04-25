using BenchmarkDotNet.Attributes;
using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Benchmarks;

[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("Cache")]
public class EmbeddingCacheBenchmarks
{
    private InMemoryLruEmbeddingCache _cache     = null!;
    private InMemoryLruEmbeddingCache _fullCache  = null!;
    private Embedding<float>          _embedding  = null!;

    private const string HitKey  = "the quick brown fox";
    private const string MissKey = "this key is not in the cache";

    [GlobalSetup]
    public void Setup()
    {
        _embedding = new Embedding<float>(new float[256]);

        _cache = new InMemoryLruEmbeddingCache(capacity: 1024);
        _cache.Set(HitKey, _embedding);

        // pre-fill to capacity to benchmark eviction cost
        _fullCache = new InMemoryLruEmbeddingCache(capacity: 128);
        for (var i = 0; i < 128; i++)
            _fullCache.Set($"key-{i}", _embedding);
    }

    [Benchmark(Baseline = true, Description = "TryGet — cache hit")]
    public bool TryGet_Hit()
    {
        _cache.TryGet(HitKey, out _);
        return true;
    }

    [Benchmark(Description = "TryGet — cache miss")]
    public bool TryGet_Miss()
    {
        _cache.TryGet(MissKey, out _);
        return true;
    }

    [Benchmark(Description = "Set — new key, capacity not reached")]
    public void Set_NewKey()
    {
        // use a rotating key so each iteration is a new key but cache doesn't fill up
        // (capacity 1024, we only ever have ~10 distinct keys in rotation)
        _cache.Set($"rotating-{Environment.TickCount64 % 10}", _embedding);
    }

    [Benchmark(Description = "Set — existing key (update, no eviction)")]
    public void Set_ExistingKey() => _cache.Set(HitKey, _embedding);

    [Benchmark(Description = "Set — at capacity (triggers eviction)")]
    public void Set_AtCapacity()
    {
        // always a new key against the full cache → triggers eviction each time
        _fullCache.Set($"new-{Guid.NewGuid()}", _embedding);
    }
}
