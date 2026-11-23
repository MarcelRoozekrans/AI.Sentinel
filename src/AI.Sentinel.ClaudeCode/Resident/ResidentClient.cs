using System.Net.Sockets;
using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The hook side of the local channel. Every call is bounded by a budget, and a process that is missing, slow or
/// broken is no answer, never an exception: the hook then evaluates in-process.</summary>
internal sealed class ResidentClient(ResidentSettings settings)
{
    public ResidentSettings Settings { get; } = settings;

    public async Task<bool> PingAsync() => (await SendAsync(new ResidentRequest { Op = ResidentOps.Ping }, Settings.Budget).ConfigureAwait(false))?.Ok == true;

    public async Task<bool> ShutdownAsync() => (await SendAsync(new ResidentRequest { Op = ResidentOps.Shutdown }, Settings.Budget).ConfigureAwait(false))?.Ok == true;

    /// <summary>Asks the process to evaluate a policy folder. <see langword="null"/> when no answer came within the budget or the process
    /// could not evaluate it; the hook then evaluates in-process.</summary>
    /// <param name="folder">The policy folder.</param>
    /// <param name="version">The version of the folder the hook read.</param>
    /// <param name="cacheDirectory">Where the compiled forms are kept.</param>
    /// <param name="inputJson">The policy input.</param>
    public Policy.Rego.RegoDecision? Evaluate(string folder, string version, string cacheDirectory, string inputJson)
    {
        var request = new ResidentRequest
        {
            Op = ResidentOps.Evaluate,
            Folder = folder,
            Version = version,
            CacheDirectory = cacheDirectory,
            Input = inputJson,
        };
        // The exchange is bounded by the budget inside SendAsync, so waiting for it here cannot hang.
        var response = Task.Run(() => SendAsync(request, Settings.Budget)).GetAwaiter().GetResult();
        return response is null ? null : ResidentDecisionWire.FromResponse(response);
    }

    /// <summary>Sends one request and returns the answer, or <see langword="null"/> when none came within <paramref name="budget"/>.</summary>
    public async Task<ResidentResponse?> SendAsync(ResidentRequest request, TimeSpan budget)
    {
        ArgumentNullException.ThrowIfNull(request);
        var path = ResidentPaths.Socket(Settings);
        if (!File.Exists(path) || ResidentPaths.SocketPathProblem(path) is not null)
        {
            return null;
        }

        using var limit = new CancellationTokenSource(budget);
        using var socket = ResidentChannel.NewSocket();
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), limit.Token).ConfigureAwait(false);
            using var stream = new NetworkStream(socket, ownsSocket: false);
            await ResidentChannel.WriteAsync(stream, request, ResidentJsonContext.Default.ResidentRequest, limit.Token).ConfigureAwait(false);
            var line = await ResidentChannel.ReadLineAsync(stream, limit.Token).ConfigureAwait(false);
            return line is null ? null : JsonSerializer.Deserialize(line, ResidentJsonContext.Default.ResidentResponse);
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException or JsonException)
        {
            return null;
        }
    }
}
