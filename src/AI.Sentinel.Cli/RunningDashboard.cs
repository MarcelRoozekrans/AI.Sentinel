using AI.Sentinel.Sqlite;
using Microsoft.AspNetCore.Builder;

namespace AI.Sentinel.Cli;

/// <summary>A started dashboard. Disposing stops the server and closes the approval and audit files.</summary>
public sealed class RunningDashboard : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly IAsyncDisposable? _approvalStore;
    private readonly SqliteAuditStore _store;

    internal RunningDashboard(WebApplication app, SqliteAuditStore store, IAsyncDisposable? approvalStore, Uri url)
    {
        _app = app;
        _store = store;
        _approvalStore = approvalStore;
        Url = url;
    }

    /// <summary>The dashboard address, ending in <c>/ai-sentinel/</c>.</summary>
    public Uri Url { get; }

    /// <summary>Completes when <paramref name="ct"/> is cancelled.</summary>
    public async Task WaitForShutdownAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Cancellation is the shutdown signal.
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _app.StopAsync().ConfigureAwait(false);
            await _app.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            try
            {
                if (_approvalStore is not null)
                {
                    await _approvalStore.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                await _store.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
