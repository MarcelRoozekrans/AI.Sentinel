using System.Runtime.CompilerServices;
using ZeroAlloc.Collections;

namespace AI.Sentinel.Audit;

public sealed class RingBufferAuditStore(int capacity = 10_000) : IAuditStore
{
    private readonly HeapRingBuffer<AuditEntry> _buffer = new(capacity);
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async ValueTask AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            // Overwrite oldest when full (ring buffer semantics)
            if (_buffer.IsFull)
                _buffer.TryRead(out _);
            _buffer.TryWrite(entry);
        }
        finally { _lock.Release(); }
    }

    public async IAsyncEnumerable<AuditEntry> QueryAsync(
        AuditQuery query,
        [EnumeratorCancellation] CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        AuditEntry[] snapshot;
        try { snapshot = _buffer.ToArray(); }
        finally { _lock.Release(); }

        foreach (var entry in snapshot)
        {
            if (ct.IsCancellationRequested) yield break;
            if (query.MinSeverity.HasValue && entry.Severity < query.MinSeverity) continue;
            if (query.From.HasValue && entry.Timestamp < query.From) continue;
            if (query.To.HasValue && entry.Timestamp > query.To) continue;
            yield return entry;
        }
    }
}
