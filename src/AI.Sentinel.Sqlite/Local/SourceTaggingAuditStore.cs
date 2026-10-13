using AI.Sentinel.Audit;

namespace AI.Sentinel.Sqlite.Local;

/// <summary>
/// Stamps <see cref="AuditEntry.Source"/> on every entry and keeps audit failures from changing a
/// CLI's decision: an append that fails is reported through <c>reportProblem</c> and the tagged entry
/// is returned unlinked instead of throwing.
/// </summary>
internal sealed class SourceTaggingAuditStore(IAuditStore inner, string source, Action<string> reportProblem) : IAuditStore
{
    private long _appendCount;

    /// <summary>Number of <see cref="AppendAsync"/> calls seen, including ones that failed.
    /// <see cref="AuditForwarding"/> forwards both, so this is what forwarders must catch up to.</summary>
    public long AppendCount => Interlocked.Read(ref _appendCount);

    public async ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(entry);
        Interlocked.Increment(ref _appendCount);
        var tagged = entry with { Source = source };
        try
        {
            return await inner.AppendAsync(tagged, ct).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // An audit failure must never change an allow, block or warn decision.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            reportProblem($"Audit entry was not recorded: {ex.GetType().Name}: {ex.Message}");
            return tagged;
        }
    }

    public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) =>
        inner.QueryAsync(query, ct);
}
