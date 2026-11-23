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
