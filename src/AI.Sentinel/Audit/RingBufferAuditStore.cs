using System.Runtime.CompilerServices;
using ZeroAlloc.Collections;

namespace AI.Sentinel.Audit;

public sealed class RingBufferAuditStore(int capacity = 10_000) : IAuditStore, IDisposable
{
    private readonly HeapRingBuffer<AuditEntry> _buffer = new(capacity);
    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _lastHash;

    public async ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(entry);
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var linked = AuditHashChain.Link(entry, _lastHash);
            // Overwrite oldest when full (ring buffer semantics). The evicted entry's hash stays
            // the PreviousHash of the new oldest entry, so the remaining chain still verifies.
            if (_buffer.IsFull)
                _buffer.TryRead(out _);
            _buffer.TryWrite(linked);
            _lastHash = linked.Hash;
            return linked;
        }
        finally { _lock.Release(); }
    }

    public async IAsyncEnumerable<AuditEntry> QueryAsync(
        AuditQuery query,
        [EnumeratorCancellation] CancellationToken ct)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        AuditEntry[] snapshot;
        try { snapshot = _buffer.ToArray(); }
        finally { _lock.Release(); }

        if (query.Reverse) Array.Reverse(snapshot);  // newest-first traversal

        int yielded = 0;
        foreach (var entry in snapshot)
        {
            if (ct.IsCancellationRequested) yield break;
            if (yielded >= query.PageSize) yield break;
            if (query.MinSeverity.HasValue && entry.Severity < query.MinSeverity) continue;
            if (query.From.HasValue && entry.Timestamp < query.From) continue;
            if (query.To.HasValue && entry.Timestamp > query.To) continue;
            if (!string.IsNullOrEmpty(query.SessionId)
                && !string.Equals(entry.SessionId, query.SessionId, StringComparison.Ordinal))
                continue;
            if (query.DetectorId is not null
                && !string.Equals(entry.DetectorId, query.DetectorId, StringComparison.Ordinal))
                continue;
            if (query.PolicyCode is not null
                && !string.Equals(entry.PolicyCode, query.PolicyCode, StringComparison.Ordinal))
                continue;
            if (!string.IsNullOrEmpty(query.Source)
                && !string.Equals(entry.Source, query.Source, StringComparison.OrdinalIgnoreCase))
                continue;
            yield return entry;
            yielded++;
        }
    }

    public void Dispose() => _lock.Dispose();
}
