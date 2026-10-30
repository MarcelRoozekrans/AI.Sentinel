using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>A loopback OpenAI-compatible chat completions endpoint that answers every request with one verdict,
/// optionally after a delay, and counts the requests. It lets a host test take the SENTINEL_REVIEW_* route end to end.</summary>
public sealed class ReviewStubServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly TimeSpan _delay;
    private readonly string _body;
    private int _requests;

    public ReviewStubServer(string severity, TimeSpan? delay = null)
    {
        _delay = delay ?? TimeSpan.Zero;
        var content = $"{{\"severity\":\"{severity}\",\"reason\":\"stub\"}}".Replace("\"", "\\\"", StringComparison.Ordinal);
        _body = $"{{\"choices\":[{{\"index\":0,\"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"}}}}]}}";

        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        Endpoint = $"http://127.0.0.1:{port}/v1/chat/completions";
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _listener.Start();
        _ = Task.Run(ServeAsync);
    }

    /// <summary>The value for SENTINEL_REVIEW_ENDPOINT.</summary>
    public string Endpoint { get; }

    /// <summary>How many requests arrived.</summary>
    public int Requests => Volatile.Read(ref _requests);

    private async Task ServeAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            HttpListenerContext context;
            try { context = await _listener.GetContextAsync().ConfigureAwait(false); }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException) { return; }

            Interlocked.Increment(ref _requests);
            _ = Task.Run(async () =>
            {
                try
                {
                    if (_delay > TimeSpan.Zero) await Task.Delay(_delay, _stop.Token).ConfigureAwait(false);
                    var bytes = Encoding.UTF8.GetBytes(_body);
                    context.Response.ContentType = "application/json";
                    await context.Response.OutputStream.WriteAsync(bytes, _stop.Token).ConfigureAwait(false);
                    context.Response.Close();
                }
                catch (Exception ex) when (ex is OperationCanceledException or HttpListenerException or ObjectDisposedException or IOException)
                {
                    // The client gave up, or the test ended.
                }
            });
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Close();
        _stop.Dispose();
    }
}
