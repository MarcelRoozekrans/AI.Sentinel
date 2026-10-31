using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>A loopback HTTP endpoint on a free port that records the JSON body of each POST and answers 200.</summary>
internal sealed class WebhookListener : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly Task _loop;
    private readonly List<JsonDocument> _bodies = [];

    public WebhookListener()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        Url = new Uri($"http://127.0.0.1:{port}/");
        _listener.Prefixes.Add(Url.AbsoluteUri);
        _listener.Start();
        _loop = Task.Run(LoopAsync);
    }

    public Uri Url { get; }

    /// <summary>The bodies received so far.</summary>
    public IReadOnlyList<JsonDocument> Bodies
    {
        get { lock (_bodies) { return [.. _bodies]; } }
    }

    private async Task LoopAsync()
    {
        while (_listener.IsListening)
        {
            try
            {
                var ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
                var body = await reader.ReadToEndAsync().ConfigureAwait(false);
                lock (_bodies) { _bodies.Add(JsonDocument.Parse(body)); }
                ctx.Response.StatusCode = 200;
                ctx.Response.Close();
            }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }
        }
    }

    public void Dispose()
    {
        _listener.Close();
        _loop.GetAwaiter().GetResult();
        foreach (var b in _bodies) b.Dispose();
    }
}
