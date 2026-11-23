using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>Runs the loader for the life of the host and wakes it when the folder changes.</summary>
internal sealed class PolicyFolderService(PolicyFolderLoader loader, string folder, ILogger<PolicyFolderService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var watchers = new List<FileSystemWatcher>();
        try
        {
            Watch(watchers, Path.GetFullPath(folder), recursive: true);
            // A link swapped in the parent, as git-sync does, is seen at the parent.
            if (Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder))) is { } parent)
            {
                Watch(watchers, parent, recursive: false);
            }

            await loader.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // The host is stopping.
        }
        finally
        {
            foreach (var watcher in watchers)
            {
                watcher.Dispose();
            }
        }
    }

    private void Watch(List<FileSystemWatcher> watchers, string path, bool recursive)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            var watcher = new FileSystemWatcher(path) { IncludeSubdirectories = recursive, EnableRaisingEvents = false };
            watcher.Changed += (_, _) => loader.Notify();
            watcher.Created += (_, _) => loader.Notify();
            watcher.Deleted += (_, _) => loader.Notify();
            watcher.Renamed += (_, _) => loader.Notify();
            watcher.Error += (_, _) => loader.Notify();
            watcher.EnableRaisingEvents = true;
            watchers.Add(watcher);
        }
        catch (Exception e) when (e is IOException or ArgumentException or PlatformNotSupportedException)
        {
            // The poll interval still finds the change.
            log.LogWarning("The policy folder cannot be watched ({Error}); it is polled instead.", e.GetType().Name);
        }
    }
}
