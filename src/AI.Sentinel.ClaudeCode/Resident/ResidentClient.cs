using System.Net.Sockets;
using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The hook side of the local channel. Every call is bounded by a budget, and a process that is missing, slow or
/// broken is no answer, never an exception: the hook then evaluates in-process. The one exception is a bundle that failed while it
/// ran in the process (#716): that was an evaluation, and <see cref="Evaluate"/> throws <see cref="Policy.Rego.PolicyBundleException"/>.</summary>
internal sealed class ResidentClient(ResidentSettings settings)
{
    public ResidentSettings Settings { get; } = settings;

    public async Task<bool> PingAsync() => (await SendAsync(new ResidentRequest { Op = ResidentOps.Ping }, Settings.Budget).ConfigureAwait(false))?.Ok == true;

    public async Task<bool> ShutdownAsync() => (await SendAsync(new ResidentRequest { Op = ResidentOps.Shutdown }, Settings.Budget).ConfigureAwait(false))?.Ok == true;

    /// <summary>Asks the process to evaluate a policy folder. <see langword="null"/> when no answer came within the budget or the process
    /// could not load the module; the hook then evaluates in-process. The budget runs from the moment of the call, so the time the exchange
    /// waits to be scheduled counts against it, and an exchange that is still running when it ends is cancelled before this returns.</summary>
    /// <param name="folder">The policy folder.</param>
    /// <param name="version">The version of the folder the hook read.</param>
    /// <param name="cacheDirectory">Where the compiled forms are kept.</param>
    /// <param name="inputJson">The policy input.</param>
    /// <param name="budget">How long to wait; <see cref="ResidentSettings.Budget"/> when <see langword="null"/>.</param>
    /// <exception cref="Policy.Rego.PolicyBundleException">The bundle failed while it ran in the process.</exception>
    public Policy.Rego.RegoDecision? Evaluate(string folder, string version, string cacheDirectory, string inputJson, TimeSpan? budget = null)
    {
        var request = new ResidentRequest
        {
            Op = ResidentOps.Evaluate,
            Folder = folder,
            Version = version,
            CacheDirectory = cacheDirectory,
            Input = inputJson,
        };
        var wait = budget ?? Settings.Budget;
        if (wait <= TimeSpan.Zero)
        {
            return null;
        }

        var limit = new CancellationTokenSource(wait);
        // Whoever takes the claim first disposes the source: the exchange when it ends first, this call when it gives up first, and
        // then only after it has cancelled. Cancel never runs on a disposed source.
        var claimed = 0;
        var exchange = Task.Run(() => SendAsync(request, limit.Token), CancellationToken.None);
        _ = exchange.ContinueWith(
            _ =>
            {
                if (Interlocked.Exchange(ref claimed, 1) == 0)
                {
                    limit.Dispose();
                }
            },
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        // WaitAny does not throw for a failed exchange; the result below does, with the original exception.
        if (Task.WaitAny([exchange], wait) < 0)
        {
            if (Interlocked.Exchange(ref claimed, 1) == 0)
            {
                limit.Cancel();
                limit.Dispose();
            }

            return null;
        }

        return exchange.GetAwaiter().GetResult() is { } response ? ResidentDecisionWire.FromResponse(response) : null;
    }

    /// <summary>Sends one request and returns the answer, or <see langword="null"/> when none came within <paramref name="budget"/>.</summary>
    public async Task<ResidentResponse?> SendAsync(ResidentRequest request, TimeSpan budget)
    {
        using var limit = new CancellationTokenSource(budget);
        return await SendAsync(request, limit.Token).ConfigureAwait(false);
    }

    private async Task<ResidentResponse?> SendAsync(ResidentRequest request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        var path = ResidentPaths.Socket(Settings);
        if (!File.Exists(path) || ResidentPaths.SocketPathProblem(path) is not null)
        {
            return null;
        }

        using var socket = ResidentChannel.NewSocket();
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), token).ConfigureAwait(false);
            using var stream = new NetworkStream(socket, ownsSocket: false);
            await ResidentChannel.WriteAsync(stream, request, ResidentJsonContext.Default.ResidentRequest, token).ConfigureAwait(false);
            var line = await ResidentChannel.ReadLineAsync(stream, token).ConfigureAwait(false);
            return line is null ? null : JsonSerializer.Deserialize(line, ResidentJsonContext.Default.ResidentResponse);
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException or JsonException)
        {
            return null;
        }
    }
}
