using System.Text.Json;

namespace AI.Sentinel.Audit;

/// <summary>Audit forwarder that appends each entry as a JSON line to a local NDJSON file. Operators ship the file via Filebeat / Vector / Fluent Bit etc. Direct file append; no buffering needed (file I/O is microsecond-scale).</summary>
public sealed class NdjsonFileAuditForwarder : IAuditForwarder, IAsyncDisposable
{
    private readonly FileStream _stream;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private int _disposed;   // 0 = open, 1 = disposed. Interlocked-gated so exactly one caller tears down.

    public NdjsonFileAuditForwarder(NdjsonFileAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.FilePath, nameof(options));
        _stream = new FileStream(options.FilePath, FileMode.Append, FileAccess.Write, FileShare.Read);
        // NewLine = "\n" forces LF terminators so NDJSON output is identical on
        // Windows + Linux + macOS. SIEMs accept either, but byte-identical output
        // simplifies debugging cross-platform deployments.
        _writer = new StreamWriter(_stream) { AutoFlush = false, NewLine = "\n" };
    }

    public async ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(batch);
        if (batch.Count == 0)
        {
            return;
        }

        // Cheap pre-lock check: skip a send that arrives after shutdown has begun. The
        // authoritative check is inside the lock below — this only avoids taking the lock
        // (and racing WaitAsync against _lock.Dispose) in the common post-dispose case.
        if (Volatile.Read(ref _disposed) == 1)
        {
            LogDropped();
            return;
        }

        var locked = false;
        try
        {
            await _lock.WaitAsync(ct).ConfigureAwait(false);
            locked = true;
            // DisposeAsync sets _disposed and then closes the writer/stream. It waits on this
            // same lock, so if it already ran the stream is gone — writing would raise
            // ObjectDisposedException. Drop the batch instead (fail-open shutdown).
            if (Volatile.Read(ref _disposed) == 1)
            {
                LogDropped();
                return;
            }
            foreach (var entry in batch)
            {
                var line = JsonSerializer.Serialize(entry, AuditJsonContext.Default.AuditEntry);
                await _writer.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false);
            }
            await _writer.FlushAsync(ct).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // IAuditForwarder.SendAsync MUST NOT throw — fail-open contract.
        catch (Exception ex)
        {
            // Surface IO / serialization / post-dispose failures via stderr; never propagate.
            // Matches the swallow-and-log posture of BufferingAuditForwarder.FlushAsync
            // and AzureSentinelAuditForwarder.SendAsync.
            Console.Error.WriteLine($"event=audit_forward action=send_error forwarder=NdjsonFile error={ex.GetType().Name}");
        }
#pragma warning restore CA1031
        finally
        {
            if (locked)
            {
                try { _lock.Release(); }
                catch (ObjectDisposedException) { /* lock disposed concurrently; nothing to release */ }
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Gate teardown to exactly one caller. This must happen BEFORE touching _lock so a
        // second (or concurrent) DisposeAsync returns without awaiting WaitAsync on a
        // semaphore the first call has already disposed — which is itself an
        // ObjectDisposedException, the very failure mode we are closing.
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        // Acquire the write lock before closing the stream so disposal waits for any
        // in-flight SendAsync to finish its WriteLineAsync/FlushAsync. Without this,
        // _writer.DisposeAsync (which flushes) runs concurrently on the same FileStream
        // as an in-flight write and throws "The stream is currently in use by a previous
        // operation on the stream." — on the audit-log shutdown path, where the tail of
        // the trail is the most valuable part.
        await _lock.WaitAsync().ConfigureAwait(false);
        try
        {
            await _writer.DisposeAsync().ConfigureAwait(false);
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
        _lock.Dispose();
    }

    private static void LogDropped() =>
        Console.Error.WriteLine("event=audit_forward action=send_dropped forwarder=NdjsonFile reason=disposed");
}
