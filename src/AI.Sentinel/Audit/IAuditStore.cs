using ZeroAlloc.Telemetry;

namespace AI.Sentinel.Audit;

[Instrument("ai.sentinel")]
public interface IAuditStore
{
    [Trace("audit.append")]
    [Count("audit.entries")]
    [Histogram("audit.append.ms")]
    ValueTask AppendAsync(AuditEntry entry, CancellationToken ct);
    IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct);
}
