namespace AI.Sentinel.Tests.AspNetCore.SessionControl;

/// <summary>Plays a network that drops a stream and then refuses a few attempts to connect again.</summary>
internal sealed class CuttableHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    private readonly Lock _gate = new();
    private readonly List<CancellationTokenSource> _open = [];
    private int _refuse;
    private int _connections;

    public int Connections => Volatile.Read(ref _connections);

    /// <summary>Ends every open stream and refuses the next <paramref name="attemptsToRefuse"/> attempts.</summary>
    public void Cut(int attemptsToRefuse)
    {
        lock (_gate)
        {
            _refuse = attemptsToRefuse;
            foreach (var cts in _open)
            {
                cts.Cancel();
            }

            _open.Clear();
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_refuse > 0)
            {
                _refuse--;
                throw new HttpRequestException("the network is down");
            }
        }

        var response = await base.SendAsync(request, cancellationToken);
        if (request.RequestUri!.AbsolutePath.EndsWith("/events", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _connections);
            var cut = new CancellationTokenSource();
            lock (_gate)
            {
                _open.Add(cut);
            }

            response.Content = new StreamContent(new CuttableStream(await response.Content.ReadAsStreamAsync(cancellationToken), cut.Token));
        }

        return response;
    }

    private sealed class CuttableStream(Stream inner, CancellationToken cut) : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, cut);
            try
            {
                return await inner.ReadAsync(buffer, linked.Token);
            }
            catch (OperationCanceledException e) when (cut.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new IOException("the connection was cut", e);
            }
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
