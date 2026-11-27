using Microsoft.Extensions.Hosting;

namespace AI.Sentinel.AspNetCore.ServerApprovals;

/// <summary>Deletes the decided approval requests of <see cref="ServerApprovalStore"/> once their retention is over, so a server that
/// gets no requests does not keep a tool input past it. Pending requests are left alone.</summary>
internal sealed class ServerApprovalRetentionService(ServerApprovalStore store, TimeProvider time, TimeSpan? interval = null) : BackgroundService
{
    /// <summary>How often the store is swept.</summary>
    public static readonly TimeSpan DefaultInterval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(interval ?? DefaultInterval, time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                store.PurgeExpired();
            }
        }
        catch (OperationCanceledException)
        {
            // The host is stopping.
        }
    }
}
