namespace AI.Sentinel.Audit;

public interface IAuditStore
{
    ValueTask AppendAsync(AuditEntry entry, CancellationToken ct);
    IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct);
}
