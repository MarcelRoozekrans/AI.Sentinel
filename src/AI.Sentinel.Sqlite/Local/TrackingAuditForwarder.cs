using AI.Sentinel.Audit;

namespace AI.Sentinel.Sqlite.Local;

/// <summary>Counts the entries <paramref name="inner"/> has finished sending, so a CLI can wait for
/// fire-and-forget forwards before it exits. A send that throws still counts as finished.</summary>
internal sealed class TrackingAuditForwarder(IAuditForwarder inner) : IAuditForwarder, IAsyncDisposable
{
    private long _entriesSent;

    /// <summary>Entries whose send has finished, successfully or not.</summary>
    public long EntriesSent => Interlocked.Read(ref _entriesSent);

    public async ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(batch);
        try
        {
            await inner.SendAsync(batch, ct).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Add(ref _entriesSent, batch.Count);
        }
    }

    public async ValueTask DisposeAsync()
    {
        switch (inner)
        {
            case IAsyncDisposable asyncDisposable:
                await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                break;
            case IDisposable disposable:
                disposable.Dispose();
                break;
        }
    }
}
