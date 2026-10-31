using System.Runtime.CompilerServices;

namespace AI.Sentinel.Audit;

public sealed class RingBufferAuditStore(int capacity = 10_000) : IAuditStore, IDisposable
{
    // Owned circular array: HeapRingBuffer has no indexer, so a newest-first, filtered walk would
    // need a full copy of the buffer on every query. _head is the slot of the oldest entry.
    private readonly AuditEntry[] _buffer = new AuditEntry[capacity > 0
        ? capacity
        : throw new ArgumentOutOfRangeException(nameof(capacity), capacity, "Capacity must be positive.")];
    private readonly SemaphoreSlim _lock = new(1, 1);
    private int _head;
    private int _count;
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
            if (_count == _buffer.Length)
            {
                _buffer[_head] = linked;
                _head = (_head + 1) % _buffer.Length;
            }
            else
            {
                _buffer[(_head + _count) % _buffer.Length] = linked;
                _count++;
            }
            _lastHash = linked.Hash;
            return linked;
        }
        finally { _lock.Release(); }
    }

    public async IAsyncEnumerable<AuditEntry> QueryAsync(
        AuditQuery query,
        [EnumeratorCancellation] CancellationToken ct)
    {
        // Filter in place under the lock and keep only the page, so a query never copies the buffer.
        var page = new List<AuditEntry>(Math.Clamp(query.PageSize, 0, 64));
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            for (int i = 0; i < _count && page.Count < query.PageSize; i++)
            {
                var offset = query.Reverse ? _count - 1 - i : i;  // reverse: newest-first traversal
                var entry = _buffer[(_head + offset) % _buffer.Length];
                if (Matches(entry, query)) page.Add(entry);
            }
        }
        finally { _lock.Release(); }

        foreach (var entry in page)
        {
            if (ct.IsCancellationRequested) yield break;
            yield return entry;
        }
    }

    private static bool Matches(AuditEntry entry, AuditQuery query)
    {
        if (query.MinSeverity.HasValue && entry.Severity < query.MinSeverity) return false;
        if (query.From.HasValue && entry.Timestamp < query.From) return false;
        if (query.To.HasValue && entry.Timestamp > query.To) return false;
        if (!string.IsNullOrEmpty(query.SessionId)
            && !string.Equals(entry.SessionId, query.SessionId, StringComparison.Ordinal))
            return false;
        if (query.DetectorId is not null
            && !string.Equals(entry.DetectorId, query.DetectorId, StringComparison.Ordinal))
            return false;
        if (query.PolicyCode is not null
            && !string.Equals(entry.PolicyCode, query.PolicyCode, StringComparison.Ordinal))
            return false;
        if (!string.IsNullOrEmpty(query.Source)
            && !string.Equals(entry.Source, query.Source, StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    public void Dispose() => _lock.Dispose();
}
