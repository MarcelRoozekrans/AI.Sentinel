using System.Globalization;
using System.Text;
using System.Threading.Channels;

namespace AI.Sentinel.Audit;

/// <summary>Decorates an <see cref="IAuditForwarder"/> with channel-backed batching. Drops on overflow + increments <see cref="DroppedCount"/>; rate-limits stderr log of drops to once per second.</summary>
public sealed class BufferingAuditForwarder<TInner> : IAuditForwarder, IAsyncDisposable
    where TInner : IAuditForwarder
{
    private readonly TInner _inner;
    private readonly BufferingAuditForwarderOptions _options;
    private readonly Channel<AuditEntry> _channel;
    private readonly Task _readerTask;
    private readonly CancellationTokenSource _cts = new();
    private long _droppedCount;
    private long _lastDropLogTicks;

    /// <summary>Total number of entries dropped due to channel overflow.</summary>
    public long DroppedCount => Interlocked.Read(ref _droppedCount);

    public BufferingAuditForwarder(TInner inner, BufferingAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(options);
        _inner = inner;
        _options = options;
        // Use Wait + non-blocking TryWrite so we can detect overflow ourselves;
        // the built-in DropWrite mode silently discards (TryWrite still returns true) which
        // would defeat the DroppedCount counter.
        _channel = Channel.CreateBounded<AuditEntry>(new BoundedChannelOptions(options.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });
        _readerTask = Task.Run(() => ReadLoopAsync(_cts.Token));
    }

    public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        foreach (var entry in batch)
        {
            if (!_channel.Writer.TryWrite(entry))
            {
                OnDrop();
            }
        }
        return ValueTask.CompletedTask;
    }

    private void OnDrop()
    {
        Interlocked.Increment(ref _droppedCount);

        // Rate-limit stderr to once per second to avoid log floods on outage
        var nowTicks = DateTime.UtcNow.Ticks;
        var lastTicks = Interlocked.Read(ref _lastDropLogTicks);
        if (nowTicks - lastTicks > TimeSpan.TicksPerSecond
            && Interlocked.CompareExchange(ref _lastDropLogTicks, nowTicks, lastTicks) == lastTicks)
        {
            LogStderr(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"] = "audit_forward",
                ["action"] = "drop",
                ["dropped"] = Interlocked.Read(ref _droppedCount).ToString(CultureInfo.InvariantCulture),
                ["forwarder"] = typeof(TInner).Name,
            });
        }
    }

    /// <summary>Writes a key=value line to stderr. Lives here (not <c>AI.Sentinel.Mcp.Logging.StderrLogger</c>) because <c>AI.Sentinel</c> cannot reference its own consumer.</summary>
    private static void LogStderr(IReadOnlyDictionary<string, string> fields)
    {
        var sb = new StringBuilder();
        var first = true;
        foreach (var kvp in fields)
        {
            if (!first)
            {
                sb.Append(' ');
            }
            sb.Append(kvp.Key).Append('=').Append(kvp.Value);
            first = false;
        }
        Console.Error.WriteLine(sb.ToString());
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var batch = new List<AuditEntry>(_options.MaxBatchSize);
        var lastFlush = DateTime.UtcNow;
        var writerCompleted = false;

        while (!ct.IsCancellationRequested && !writerCompleted)
        {
            try
            {
                writerCompleted = !await TryReadIntoBatchAsync(batch, lastFlush, ct).ConfigureAwait(false);

                if (batch.Count >= _options.MaxBatchSize ||
                    (batch.Count > 0 && DateTime.UtcNow - lastFlush >= _options.MaxFlushInterval))
                {
                    await FlushAsync(batch, ct).ConfigureAwait(false);
                    batch = new List<AuditEntry>(_options.MaxBatchSize);
                    lastFlush = DateTime.UtcNow;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                LogStderr(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["event"] = "audit_forward",
                    ["action"] = "reader_error",
                    ["error"] = ex.GetType().Name,
                });
            }
        }

        await DrainAndFlushAsync(batch).ConfigureAwait(false);
    }

    /// <summary>Reads one entry into <paramref name="batch"/>, bounded by the flush-interval timeout. Returns false when the channel is closed.</summary>
    private async Task<bool> TryReadIntoBatchAsync(List<AuditEntry> batch, DateTime lastFlush, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var elapsed = DateTime.UtcNow - lastFlush;
        var remaining = _options.MaxFlushInterval - elapsed;
        if (remaining > TimeSpan.Zero)
        {
            timeoutCts.CancelAfter(remaining);
        }

        try
        {
            var entry = await _channel.Reader.ReadAsync(timeoutCts.Token).ConfigureAwait(false);
            batch.Add(entry);
        }
        catch (ChannelClosedException)
        {
            return false;
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            // interval timeout — caller flushes whatever we have
        }
        return true;
    }

    /// <summary>Drains any remaining entries from the channel and emits a final flush on shutdown.</summary>
    private async Task DrainAndFlushAsync(List<AuditEntry> batch)
    {
        while (_channel.Reader.TryRead(out var pending))
        {
            batch.Add(pending);
            if (batch.Count >= _options.MaxBatchSize)
            {
                await FlushAsync(batch, CancellationToken.None).ConfigureAwait(false);
                batch = new List<AuditEntry>(_options.MaxBatchSize);
            }
        }

        if (batch.Count > 0)
        {
            await FlushAsync(batch, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task FlushAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        try
        {
            await _inner.SendAsync(batch, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogStderr(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"] = "audit_forward",
                ["action"] = "flush_error",
                ["forwarder"] = typeof(TInner).Name,
                ["error"] = ex.GetType().Name,
            });
        }
    }

    public async ValueTask DisposeAsync()
    {
        _channel.Writer.Complete();
        // Signal cancellation BEFORE waiting so a hung inner forwarder can observe the
        // token and abort within the 2-second budget. Without this, a stuck SendAsync
        // would force WaitAsync to throw TimeoutException and leave the reader task
        // running detached against a CTS we're about to dispose.
        _cts.Cancel();
        try
        {
            await _readerTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (TimeoutException) { /* reader stuck — give up */ }
        catch (OperationCanceledException) { /* expected when cancellation propagates */ }
        _cts.Dispose();
    }
}
