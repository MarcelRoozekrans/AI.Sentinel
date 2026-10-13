using ZeroAlloc.Telemetry;

namespace AI.Sentinel.Audit;

[Instrument("ai.sentinel")]
public interface IAuditStore
{
    /// <summary>
    /// Appends <paramref name="entry"/> to the end of the hash chain and returns it as stored.
    /// </summary>
    /// <remarks>
    /// The store owns the chain: under its write lock it replaces the caller's
    /// <see cref="AuditEntry.Hash"/> and <see cref="AuditEntry.PreviousHash"/> with
    /// <see cref="AuditHashChain.Link"/> applied to the hash of the entry it appended last.
    /// Forward the returned entry, not the one passed in, so downstream systems receive the
    /// same hashes and can verify the chain themselves.
    /// </remarks>
    [Trace("audit.append")]
    [Count("audit.entries")]
    [Histogram("audit.append.ms")]
    ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct);
    IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct);
}
