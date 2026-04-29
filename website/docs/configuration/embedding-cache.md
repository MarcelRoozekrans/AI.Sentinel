---
sidebar_position: 3
title: Embedding cache
---

# Embedding cache

Semantic detectors call `IEmbeddingGenerator<string, Embedding<float>>` for every scanned message. By default, results are cached in-process via `IEmbeddingCache` (LRU-bounded) so repeat content doesn't re-hit the embedding API.

```csharp
opts.EmbeddingGenerator = new OpenAIEmbeddingGenerator(...);
opts.EmbeddingCache = new InMemoryLruEmbeddingCache(capacity: 10_000);
```

> Full embedding cache guide — TTL policies, cache implementations, sharing across pipelines — coming soon.
