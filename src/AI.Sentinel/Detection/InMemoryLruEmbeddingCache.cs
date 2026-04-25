using System.Runtime.InteropServices;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public sealed class InMemoryLruEmbeddingCache : IEmbeddingCache
{
    private readonly int _capacity;
    private readonly Dictionary<string, (Embedding<float> Value, long Tick)> _store;

#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _lock = new();
#else
    private readonly object _lock = new();
#endif

    private long _tick;

    public InMemoryLruEmbeddingCache(int capacity = 1024)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _capacity = capacity;
        _store = new Dictionary<string, (Embedding<float>, long)>(StringComparer.Ordinal);
    }

    public bool TryGet(string text, out Embedding<float> embedding)
    {
        lock (_lock)
        {
            if (!_store.TryGetValue(text, out var entry))
            {
                embedding = default!;
                return false;
            }
            _store[text] = (entry.Value, ++_tick);
            embedding = entry.Value;
            return true;
        }
    }

    public void Set(string text, Embedding<float> embedding)
    {
        lock (_lock)
        {
            if (_store.Count >= _capacity)
                Evict();
            _store[text] = (embedding, ++_tick);
        }
    }

    private void Evict()
    {
        var toRemove = _store
            .OrderBy(kvp => kvp.Value.Tick)
            .Take(_store.Count / 2)
            .Select(kvp => kvp.Key)
            .ToList();
        foreach (ref readonly var key in CollectionsMarshal.AsSpan(toRemove))
            _store.Remove(key);
    }
}
