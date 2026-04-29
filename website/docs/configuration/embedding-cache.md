---
sidebar_position: 3
title: Embedding cache
---

# Embedding cache

Semantic detectors call `IEmbeddingGenerator<string, Embedding<float>>` for every scanned message. Without caching, that's an LLM API round-trip per detector per scan — fine for occasional calls, expensive at scale. The embedding cache short-circuits repeats.

## Default behavior

`AddAISentinel` registers an `InMemoryLruEmbeddingCache` automatically — 1024-entry LRU, in-process. Hits are sub-microsecond; misses fall through to your `IEmbeddingGenerator`.

```csharp
services.AddAISentinel(opts =>
{
    opts.EmbeddingGenerator = new OpenAIEmbeddingGenerator(/* ... */);
    // opts.EmbeddingCache is auto-wired to InMemoryLruEmbeddingCache(1024)
});
```

You only need to think about the cache when you want to:

- Resize the in-memory LRU
- Share cache across processes (Redis, SQLite, etc.)
- Disable caching entirely for testing

## How semantic detectors use it

Every `SemanticDetectorBase` subclass goes through this path on each scan:

```
1. cache.TryGet(messageText, out vector)
2. on miss: vector = await embeddingGenerator.GenerateAsync(messageText)
3. cache.Set(messageText, vector)
4. cosine-compare vector against the detector's reference example vectors
```

The detector's reference examples are embedded **once** (lazily on first scan) and cached internally — they don't churn the LRU. The LRU's job is to dedupe **incoming-message** embeddings so the same prompt scanned twice within the cache window costs zero embedding calls.

## Cost model

Without the cache, a single scan with N semantic detectors is N embedding calls (the per-detector cosine compare is free; embedding the input is the cost). With the cache:

- **First scan of a new message** — 1 embedding call, populates cache
- **Subsequent scans of the same message text within the LRU window** — 0 calls
- **Scan of a different message** — 1 call (and possibly evicts the oldest entry)

Real-world hit rates depend heavily on traffic shape. For chat workloads with many unique prompts, the cache mostly helps deduplicate the **two passes per call** (prompt scan and response scan happen back-to-back; if your assistant echoes the prompt, the response-pass embedding is free).

## Customizing capacity

`InMemoryLruEmbeddingCache` is the default; instantiate with a larger capacity if your traffic pattern justifies it:

```csharp
services.AddAISentinel(opts =>
{
    opts.EmbeddingGenerator = realGen;
    opts.EmbeddingCache = new InMemoryLruEmbeddingCache(capacity: 10_000);
});
```

Each cached entry holds a 256-dim or 1536-dim float vector (depends on your generator's model). At 1536 dims × 4 bytes = ~6 KB per entry. 10,000 entries ≈ 60 MB. Tune for your memory budget.

## Custom cache implementations

`IEmbeddingCache` is a tiny interface:

```csharp
public interface IEmbeddingCache
{
    bool TryGet(string text, out Embedding<float> embedding);
    void Set(string text, Embedding<float> embedding);
}
```

Implementations must be thread-safe — the pipeline calls them concurrently across detectors.

### Redis-backed cache

```csharp
public sealed class RedisEmbeddingCache(IConnectionMultiplexer redis) : IEmbeddingCache
{
    private readonly IDatabase _db = redis.GetDatabase();

    public bool TryGet(string text, out Embedding<float> embedding)
    {
        var bytes = _db.StringGet(Key(text));
        if (!bytes.HasValue) { embedding = default!; return false; }

        var floats = MemoryMarshal.Cast<byte, float>(bytes!).ToArray();
        embedding = new Embedding<float>(floats);
        return true;
    }

    public void Set(string text, Embedding<float> embedding)
    {
        var bytes = MemoryMarshal.AsBytes(embedding.Vector.Span).ToArray();
        _db.StringSet(Key(text), bytes, expiry: TimeSpan.FromHours(1));
    }

    private static string Key(string text) =>
        $"emb:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))}";
}

services.AddAISentinel(opts =>
{
    opts.EmbeddingGenerator = realGen;
    opts.EmbeddingCache = new RedisEmbeddingCache(redis);
});
```

A Redis-backed cache is shared across all process instances — useful in horizontally-scaled deployments where the same prompts are likely to land on different replicas.

### Disabling the cache (for tests)

Pass a no-op cache when you want to force every scan to hit the generator:

```csharp
public sealed class NullEmbeddingCache : IEmbeddingCache
{
    public bool TryGet(string text, out Embedding<float> embedding)
    {
        embedding = default!;
        return false;
    }
    public void Set(string text, Embedding<float> embedding) { }
}
```

## Cache key gotchas

The cache keys on the **exact** message text. So:

- `"Hello, world"` and `"hello, world"` are different cache entries (case-sensitive)
- `"Hello, world"` and `"Hello,  world"` (extra space) are different entries
- Whitespace-only differences cost an embedding call

For strict deduplication you'd normalize the key — but be careful: the embedding is computed on the original text, so normalizing the key would change the cosine result. Most users leave the key behavior as-is.

## When cache misses dominate

If your scan-time profile shows mostly cache misses, that's normal — chat workloads are inherently high-cardinality. The cache helps most when:

- Same prompts repeat across users (templated greetings, common queries)
- Two-pass scans hit the same text (response echoes prompt)
- Multiple semantic detectors scan the same message (cache hit on the second detector and onwards)

For workloads where caching doesn't help (every prompt is unique), the cache costs ~50 ns per `TryGet` — negligible.

## Cache and `FakeEmbeddingGenerator` (testing)

`FakeEmbeddingGenerator` from `AI.Sentinel.Detectors.Sdk` is deterministic and fast — no LLM round-trip, no cost benefit from caching. The default LRU still works fine; it just doesn't add much value when the underlying generator is already free.

For [`DetectorTestBuilder`](../custom-detectors/detector-test-builder)-driven tests, cache configuration is rarely needed. The fake generator handles 1000 prompts in under a millisecond.

## Next: [Audit forwarders](../audit-forwarders/overview) — ship audit entries to external SIEMs
