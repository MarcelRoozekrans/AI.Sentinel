using System.Net.Sockets;
using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>A process that accepts every connection and never answers, in place of a resident process that is stuck.</summary>
internal sealed class SilentListener : IDisposable
{
    private readonly Socket _listener = ResidentChannel.NewSocket();
    private readonly List<Socket> _accepted = [];
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;

    public SilentListener(ResidentSettings settings)
    {
        var path = ResidentPaths.Socket(settings with { StateDirectory = ResidentPaths.Prepare(settings) });
        _listener.Bind(new UnixDomainSocketEndPoint(path));
        _listener.Listen(8);
        _loop = Task.Run(async () =>
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    _accepted.Add(await _listener.AcceptAsync(_stop.Token));
                }
            }
            catch (OperationCanceledException)
            {
                // Stopped.
            }
        });
    }

    public void Dispose()
    {
        _stop.Cancel();
        _loop.Wait(TimeSpan.FromSeconds(10));
        foreach (var socket in _accepted)
        {
            socket.Dispose();
        }

        _listener.Dispose();
        _stop.Dispose();
    }
}
