using AI.Sentinel.Sqlite;
using Microsoft.AspNetCore.Builder;

namespace AI.Sentinel.Cli;

/// <summary>A started dashboard. Disposing stops the server and closes the audit file.</summary>
public sealed class RunningDashboard : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly SqliteAuditStore _store;

    internal RunningDashboard(WebApplication app, SqliteAuditStore store, Uri url)
    {
        _app = app;
        _store = store;
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
        await _app.StopAsync().ConfigureAwait(false);
        await _app.DisposeAsync().ConfigureAwait(false);
        await _store.DisposeAsync().ConfigureAwait(false);
    }
}
