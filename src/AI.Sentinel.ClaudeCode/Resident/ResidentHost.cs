using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The resident local process (#658): one per user. It listens on a Unix domain socket in the private state folder, answers
/// the hooks, and exits after the idle timeout. A lock file opened with <see cref="FileShare.None"/> makes it a single
/// instance: the operating system releases the lock when the process ends, however it ends, so a crash leaves no stale
/// lock. No OS service is installed; a hook starts the process when it finds none.
/// </summary>
internal static class ResidentHost
{
    /// <summary>Runs until the idle timeout, a shutdown request or <paramref name="ct"/>.</summary>
    /// <param name="settings">The settings.</param>
    /// <param name="compilers">The compilers for a policy that is not cached; <see cref="RegoPolicy.DefaultCompilers"/> when
    /// <see langword="null"/>.</param>
    /// <param name="ct">Stops the process.</param>
    /// <param name="listening">Called once the socket accepts connections.</param>
    public static async Task<ResidentExit> RunAsync(
        ResidentSettings settings, IReadOnlyList<IRegoCompiler>? compilers, CancellationToken ct, Action? listening = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var dir = ResidentPaths.Prepare(settings);
        using var instance = TryTakeLock(ResidentPaths.Lock(settings));
        if (instance is null)
        {
            return ResidentExit.AlreadyRunning;
        }

        var socketPath = ResidentPaths.Socket(settings);
        if (ResidentPaths.SocketPathProblem(socketPath) is not null)
        {
            return ResidentExit.Failed;
        }

        // The lock is ours, so a socket file that is still there belongs to a process that ended without removing it.
        File.Delete(socketPath);
        using var listener = ResidentChannel.NewSocket();
        try
        {
            listener.Bind(new UnixDomainSocketEndPoint(socketPath));
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(socketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            listener.Listen(32);
        }
        catch (SocketException)
        {
            return ResidentExit.Failed;
        }

        var pidPath = ResidentPaths.Pid(settings);
        await File.WriteAllTextAsync(pidPath, Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), CancellationToken.None).ConfigureAwait(false);
        try
        {
            return await ServeAsync(listener, settings, new ResidentService(dir, compilers), ct, listening).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(socketPath);
            File.Delete(pidPath);
        }
    }

    private static async Task<ResidentExit> ServeAsync(
        Socket listener, ResidentSettings settings, ResidentService service, CancellationToken ct, Action? listening)
    {
        using var _ = service;
        using var idle = new CancellationTokenSource();
        using var shutdown = new CancellationTokenSource();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct, idle.Token, shutdown.Token);
        idle.CancelAfter(settings.IdleTimeout);
        listening?.Invoke();
        var inFlight = new List<Task>();
        while (!stop.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            idle.CancelAfter(settings.IdleTimeout);
            inFlight.RemoveAll(t => t.IsCompleted);
            inFlight.Add(HandleAsync(client, service, settings, idle, shutdown, ct));
        }

        try
        {
            await Task.WhenAll(inFlight).WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // A request that does not finish in a second is dropped with the process.
        }

        if (shutdown.IsCancellationRequested)
        {
            return ResidentExit.Shutdown;
        }

        return ct.IsCancellationRequested ? ResidentExit.Cancelled : ResidentExit.Idle;
    }

    private static FileStream? TryTakeLock(string path)
    {
        try
        {
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static async Task HandleAsync(
        Socket client, ResidentService service, ResidentSettings settings, CancellationTokenSource idle, CancellationTokenSource shutdown, CancellationToken stop)
    {
        using var socket = client;
        using var stream = new NetworkStream(socket, ownsSocket: false);
        try
        {
            // A client that connects and says nothing must not hold the process, nor keep it from idling out.
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(stop);
            limit.CancelAfter(TimeSpan.FromSeconds(10));
            var line = await ResidentChannel.ReadLineAsync(stream, limit.Token).ConfigureAwait(false);
            if (line is null)
            {
                return;
            }

            var response = Answer(line, service, shutdown);
            await ResidentChannel.WriteAsync(stream, response, ResidentJsonContext.Default.ResidentResponse, limit.Token).ConfigureAwait(false);
            idle.CancelAfter(settings.IdleTimeout);
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // The client went away or the process is stopping; there is nobody to tell.
        }
    }

    private static ResidentResponse Answer(string line, ResidentService service, CancellationTokenSource shutdown)
    {
        ResidentRequest? request;
        try
        {
            request = JsonSerializer.Deserialize(line, ResidentJsonContext.Default.ResidentRequest);
        }
        catch (JsonException)
        {
            return new ResidentResponse { Error = "the request is not JSON" };
        }

        if (request is null)
        {
            return new ResidentResponse { Error = "the request is empty" };
        }

        switch (request.Op)
        {
            case ResidentOps.Ping:
                return new ResidentResponse { Ok = true, Pid = Environment.ProcessId };
            case ResidentOps.Shutdown:
                shutdown.Cancel();
                return new ResidentResponse { Ok = true, Pid = Environment.ProcessId };
            default:
                return service.Answer(request);
        }
    }
}
