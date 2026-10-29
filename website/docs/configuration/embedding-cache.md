---
sidebar_position: 3
title: Embedding cache
---

# Embedding cache

Semantic detectors call `IEmbeddingGenerator<string, Embedding<float>>` for every scanned message. Each scan embeds a new text once, in one batch, however many semantic detectors run. Without caching, that's an LLM API round-trip per scan — fine for occasional calls, expensive at scale. The embedding cache short-circuits repeats.

## Default behavior

When `opts.EmbeddingCache` is not set, each pipeline creates one `InMemoryLruEmbeddingCache` for its scans: a 1024-entry LRU, in-process, shared by all its semantic detectors. Hits are sub-microsecond; misses fall through to your `IEmbeddingGenerator`.

Set `opts.EmbeddingCache` to size the cache or to plug in your own, for example a persistent one:

```csharp
services.AddAISentinel(opts =>
{
    opts.EmbeddingGenerator = new OpenAIEmbeddingGenerator(/* ... */);
    opts.EmbeddingCache = new InMemoryLruEmbeddingCache(capacity: 4096); // replaces the default 1024-entry cache
});
```

The generator does not have to be set on the options. When `opts.EmbeddingGenerator` is unset, the semantic detectors use the generator registered in DI, and the caches above apply to it the same way. See [Embedding generator from DI](#embedding-generator-from-di).

Beyond sharing it, you only need to think about the cache when you want to:

- Resize the in-memory LRU
- Share cache across processes (Redis, SQLite, etc.)
- Disable caching entirely for testing

## Embedding generator from DI

When `opts.EmbeddingGenerator` is `null`, AI.Sentinel uses the `IEmbeddingGenerator<string, Embedding<float>>` registered in the container. Register it the Microsoft.Extensions.AI way and its middleware, such as OpenTelemetry and logging, runs for every embedding call AI.Sentinel makes:

```csharp
services.AddEmbeddingGenerator(sp => openAiClient.GetEmbeddingClient("text-embedding-3-small").AsIEmbeddingGenerator())
    .UseOpenTelemetry();

services.AddAISentinel(opts =>
{
    opts.EmbeddingCache = new InMemoryLruEmbeddingCache(capacity: 4096); // applies to the DI generator too
});
```

- **Resolved lazily.** The generator is looked up when the provider first resolves `SentinelOptions`, never by `AddAISentinel`, so it may be registered after it.
- **Singleton.** Register it as a singleton, which is the `AddEmbeddingGenerator` default. The options are a singleton and keep the generator they resolve, so a scoped one would be captured past its scope.
- **Explicit wins.** A generator set on `opts.EmbeddingGenerator` is always used instead of the one in DI.
- **Same path.** The semantic detectors get the DI generator through the same options they would read an explicit one from, so `EmbeddingCache` and `ExampleEmbeddingCache` behave identically.
- **Test doubles.** A test host swaps the generator through ordinary DI, for example `services.AddSingleton<IEmbeddingGenerator<string, Embedding<float>>>(fake)` in a `WebApplicationFactory`; the last registration wins.
- **Named pipelines** use their own generator when they set one, and otherwise the default pipeline's: the one on the default options, or else the one in DI. The generator and the caches move together; see [Named pipelines](./named-pipelines#whats-isolated-whats-shared). A keyed generator registered with `AddKeyedEmbeddingGenerator` is not used.
- **Opt-out.** Set `opts.UseEmbeddingGeneratorFromServices = false` to keep semantic detection off although the container has a generator, for example one the app registers for its own retrieval. Only the default pipeline's setting counts.

With neither an explicit nor a DI generator, the semantic detectors return `Clean` and AI.Sentinel logs a warning when the pipeline is built. The CLIs and the MCP proxy are unaffected: they set the generator from `SENTINEL_EMBEDDING_ENDPOINT` and `SENTINEL_EMBEDDING_MODEL`.

:::caution Upgrading to 3.8
An app that already registers an `IEmbeddingGenerator<string, Embedding<float>>` for other purposes, and leaves `opts.EmbeddingGenerator` unset, now uses that generator for screening. Every screened message is embedded with it, which adds embedding cost and latency, and the semantic detectors start producing findings they did not produce before. To keep the 3.7 behaviour, set `opts.UseEmbeddingGeneratorFromServices = false`.
:::

## How semantic detectors use it

Within a pipeline, every semantic detector shares one embedding step per scan:

```
1. each detector takes the text of each new message, at most 16 (past that,
   the oldest are joined into one), and normalises redaction placeholders:
   [EMAIL_1_k3f9x2] becomes [EMAIL]
2. the pipeline merges those texts, dropping duplicates, and looks each one up:
   cache.TryGet(normalisedText, out vector)
3. on any miss: vectors = await embeddingGenerator.GenerateAsync(allMissedTexts),
   one call for the whole scan
4. for each miss: cache.Set(normalisedText, vector)
5. each detector cosine-compares its own texts' vectors against its reference
   example vectors
```

The cache key is the normalised message text, so the same message carrying a different placeholder suffix in another session still hits. Each new message is one lookup. History that is scored again, for example from a client that resends the conversation without assistant messages, and a tool result that repeats hit the cache instead of the generator.

The detector's reference examples are embedded **once** per generator instance (lazily on first scan) and kept in the process, not in the LRU. Concurrent first scans share one embedding of them, and a failed attempt is retried on the next scan. Pipelines that share a generator instance share the vectors; different generators never do. The LRU's job is to dedupe **incoming-message** embeddings so the same message scanned twice within the cache window costs zero embedding calls.

### When the generator rejects an input

A provider can reject one input, for example one over its token limit, and that must not hide the rest of the scan:

- If the batch call fails, or returns a different number of vectors than inputs, each missing text is retried on its own, one call at a time. A text the provider rejects is skipped by itself; the other texts are still scored.
- If the first two single-input calls both fail and none has succeeded, the endpoint is treated as down and the rest of the scan's texts are skipped without further calls. An outage, a rejected key or rate limiting costs the batch call plus two more.
- A failure is logged and passed to `OnDetectorFailure` once per scan, with the number of inputs that failed and the exception, never the input text. The same holds for a failure to embed the example phrases.
- A detector left with no vectors returns `Clean`, as it does without a generator. A detector whose example phrases failed still runs its rule layer, where it has one.
- Cancellation always propagates and is never reported as a failure.

## Cost model

Embedding the input is the cost; the per-detector cosine compare is free. A pipeline makes **one generator call per scan for all cache misses**, across all its semantic detectors, and none when every text hits:

- **First scan of a new message** — 1 call, populates the cache
- **A scan whose new messages are all in the cache** — 0 calls
- **A scan with several new messages, for example a batch of tool results** — still 1 call, for the ones the cache has not seen

Without the cache, every scan makes that one call for all of its new messages. If the batch fails, the retry makes one call per missing text, with the cut-off described above.

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
- The same message returns in a later scan, for example in resent history

For workloads where caching doesn't help (every prompt is unique), the cache costs ~50 ns per `TryGet` — negligible.

## Cache and `FakeEmbeddingGenerator` (testing)

`FakeEmbeddingGenerator` from `AI.Sentinel.Detectors.Sdk` is deterministic and fast — no LLM round-trip, no cost benefit from caching. The default LRU still works fine; it just doesn't add much value when the underlying generator is already free.

For [`DetectorTestBuilder`](../custom-detectors/detector-test-builder)-driven tests, cache configuration is rarely needed. The fake generator handles 1000 prompts in under a millisecond.

## Next: [Audit forwarders](../audit-forwarders/overview) — ship audit entries to external SIEMs
