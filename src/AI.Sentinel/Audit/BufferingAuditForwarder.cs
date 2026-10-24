using System.Diagnostics;
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
    private long _lastDropLogMs = long.MinValue / 2;
    // The reader's outstanding wait for data, kept across interval timeouts so no channel operation is cancelled.
    private Task<bool>? _pendingWait;

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

        // Rate-limit stderr to once per second to avoid log floods on outage. Monotonic clock:
        // a wall-clock step backwards must not silence the drop log.
        var nowMs = Environment.TickCount64;
        var lastMs = Interlocked.Read(ref _lastDropLogMs);
        if (nowMs - lastMs > 1000
            && Interlocked.CompareExchange(ref _lastDropLogMs, nowMs, lastMs) == lastMs)
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
        // Monotonic timestamp, not DateTime.UtcNow: a wall-clock step backwards (NTP, DST on a
        // misconfigured host) would otherwise hold a partial batch for as long as the step.
        var lastFlush = Stopwatch.GetTimestamp();
        var writerCompleted = false;

        while (!ct.IsCancellationRequested && !writerCompleted)
        {
            try
            {
                var read = await TryReadIntoBatchAsync(batch, lastFlush, ct).ConfigureAwait(false);
                writerCompleted = read == ReadResult.Closed;

                // A read that ended on the interval flushes without asking the clock again: the timer can fire a
                // fraction of a millisecond early, and a second clock read could then hold the batch.
                if (batch.Count >= _options.MaxBatchSize ||
                    (batch.Count > 0 && (read == ReadResult.IntervalElapsed
                                         || Stopwatch.GetElapsedTime(lastFlush) >= _options.MaxFlushInterval)))
                {
                    await FlushAsync(batch, ct).ConfigureAwait(false);
                    batch = new List<AuditEntry>(_options.MaxBatchSize);
                    lastFlush = Stopwatch.GetTimestamp();
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

    private enum ReadResult { Entry, IntervalElapsed, Closed }

    /// <summary>Reads one entry into <paramref name="batch"/>, bounded by the flush-interval timeout. With the interval
    /// already passed, it reads nothing while a batch is pending, so the caller flushes it, and waits without a
    /// timeout while none is.</summary>
    /// <remarks>No channel operation is ever cancelled. The interval is a <see cref="Task.Delay(TimeSpan, CancellationToken)"/>
    /// raced against one <see cref="ChannelReader{T}.WaitToReadAsync"/> that stays outstanding until it completes. On the
    /// .NET 10 runtime, a channel read or wait cancelled by a <c>CancelAfter</c> timer was seen to lose the entry a writer
    /// handed it, or to resume its caller twice.</remarks>
    private async Task<ReadResult> TryReadIntoBatchAsync(List<AuditEntry> batch, long lastFlush, CancellationToken ct)
    {
        var remaining = _options.MaxFlushInterval - Stopwatch.GetElapsedTime(lastFlush);
        if (remaining <= TimeSpan.Zero && batch.Count > 0)
        {
            return ReadResult.IntervalElapsed;
        }

        if (_channel.Reader.TryRead(out var entry))
        {
            batch.Add(entry);
            return ReadResult.Entry;
        }

        // DisposeAsync completes the writer before it cancels, so this wait always ends.
        var wait = _pendingWait ??= _channel.Reader.WaitToReadAsync(CancellationToken.None).AsTask();
        if (remaining > TimeSpan.Zero)
        {
            using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            // Rounded up: a timer that fires early would end the interval before it has passed.
            var delay = Task.Delay(TimeSpan.FromMilliseconds(Math.Ceiling(remaining.TotalMilliseconds)), delayCts.Token);
            if (await Task.WhenAny(wait, delay).ConfigureAwait(false) != wait)
            {
                ct.ThrowIfCancellationRequested();
                return ReadResult.IntervalElapsed;
            }

            await delayCts.CancelAsync().ConfigureAwait(false);
        }

        _pendingWait = null;
        if (!await wait.ConfigureAwait(false))
        {
            return ReadResult.Closed;
        }

        if (_channel.Reader.TryRead(out entry))
        {
            batch.Add(entry);
        }
        return ReadResult.Entry;
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
