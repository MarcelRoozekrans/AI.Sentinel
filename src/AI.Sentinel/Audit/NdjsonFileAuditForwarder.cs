using System.Buffers;
using System.Text.Json;

namespace AI.Sentinel.Audit;

/// <summary>
/// Audit forwarder that appends each entry as a JSON line to a local NDJSON file. Operators ship the file via
/// Filebeat / Vector / Fluent Bit etc. Several forwarders, in one process or in several, may append to the same
/// file: each batch is written under a lock file next to it (<c>&lt;file&gt;.lock</c>), so batches never
/// interleave or overwrite each other.
/// </summary>
public sealed class NdjsonFileAuditForwarder : IAuditForwarder, IAsyncDisposable
{
    /// <summary>Share mode for both the data file and its readers: other writers, log shippers and
    /// rotation (rename/delete) must never be locked out by this forwarder.</summary>
    private const FileShare DataFileShare = FileShare.ReadWrite | FileShare.Delete;

    private static readonly TimeSpan MaxLockBackoff = TimeSpan.FromMilliseconds(50);

    private readonly string _filePath;
    private readonly string _lockPath;
    private readonly TimeSpan _lockTimeout;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly Action<string>? _onError;
    private int _disposed;   // 0 = open, 1 = disposed. Interlocked-gated so exactly one caller tears down.

    public NdjsonFileAuditForwarder(NdjsonFileAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.FilePath, nameof(options));
        if (options.LockTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.LockTimeout, "LockTimeout must be positive.");
        }
        _onError = options.OnError;
        _filePath = Path.GetFullPath(options.FilePath);
        _lockPath = _filePath + ".lock";
        _lockTimeout = options.LockTimeout;

        // Fail fast on a bad path or missing permission, as the forwarder always has: create the file
        // if it is missing and prove it is writable. The file is opened per batch from here on, so no
        // handle is held between sends and other processes can append to it too.
        using (new FileStream(_filePath, FileMode.Append, FileAccess.Write, DataFileShare))
        {
        }
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
            // Serialise outside both locks: the whole batch becomes one buffer, written with one call.
            var payload = Serialize(batch);

            await _lock.WaitAsync(ct).ConfigureAwait(false);
            locked = true;
            // DisposeAsync sets _disposed and then waits on this same lock, so a send that gets
            // the lock after it must not write. Drop the batch instead (fail-open shutdown).
            if (Volatile.Read(ref _disposed) == 1)
            {
                LogDropped();
                return;
            }
            await AppendAsync(payload.WrittenMemory, ct).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // IAuditForwarder.SendAsync MUST NOT throw — fail-open contract.
        catch (Exception ex)
        {
            // Surface IO / serialization / lock-timeout failures via stderr; never propagate.
            // Matches the swallow-and-log posture of BufferingAuditForwarder.FlushAsync
            // and AzureSentinelAuditForwarder.SendAsync.
            Report($"event=audit_forward action=send_error forwarder=NdjsonFile error={ex.GetType().Name}");
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

    /// <summary>Writes <paramref name="payload"/> at the current end of the file while holding the cross-process
    /// lock file, so no other writer can append between the seek and the write.</summary>
    private async Task AppendAsync(ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        var fileLock = await AcquireFileLockAsync(ct).ConfigureAwait(false);
        await using (fileLock.ConfigureAwait(false))
        {
            // bufferSize 0: no FileStream buffer, so the batch reaches the OS as the single write below.
            // FileMode.Append positions at the end as of this open, which is the true end: every writer
            // appends only while it holds the lock file.
            var stream = new FileStream(
                _filePath, FileMode.Append, FileAccess.Write, DataFileShare, bufferSize: 0, FileOptions.Asynchronous);
            await using (stream.ConfigureAwait(false))
            {
                // Not cancellable once the lock is held: a write cancelled part-way would leave a
                // torn line for the next writer to append after. The token only bounds the waits.
                await stream.WriteAsync(payload, CancellationToken.None).ConfigureAwait(false);
                await stream.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Opens <c>&lt;file&gt;.lock</c> exclusively, retrying with a capped exponential backoff while another
    /// writer holds it. The lock is released by disposing the returned stream; the operating system also releases it
    /// when a writer process dies. Throws <see cref="TimeoutException"/> after the configured lock timeout.</summary>
    private async Task<FileStream> AcquireFileLockAsync(CancellationToken ct)
    {
        var deadline = Environment.TickCount64 + (long)_lockTimeout.TotalMilliseconds;
        var backoff = TimeSpan.FromMilliseconds(1);
        while (true)
        {
            try
            {
                // FileShare.None is the lock: Windows refuses a second open with a sharing violation,
                // and .NET on Unix takes an exclusive flock on the handle, which other .NET processes honour.
                return new FileStream(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, bufferSize: 0);
            }
            catch (IOException ex) when (ex is not (FileNotFoundException or DirectoryNotFoundException or PathTooLongException))
            {
                var remaining = deadline - Environment.TickCount64;
                if (remaining <= 0)
                {
                    throw new TimeoutException($"Could not lock '{_lockPath}' within {_lockTimeout}.", ex);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(backoff.TotalMilliseconds, remaining)), ct).ConfigureAwait(false);
                backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxLockBackoff.Ticks));
            }
        }
    }

    /// <summary>Serialises <paramref name="batch"/> to UTF-8 NDJSON. Lines end in LF on every platform, so output
    /// is byte-identical on Windows, Linux and macOS.</summary>
    private static ArrayBufferWriter<byte> Serialize(IReadOnlyList<AuditEntry> batch)
    {
        var buffer = new ArrayBufferWriter<byte>(256 * batch.Count);
        // Same encoder as the context, so the bytes match what JsonSerializer.Serialize would return as a string.
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Encoder = AuditJsonContext.Default.Options.Encoder });
        foreach (var entry in batch)
        {
            JsonSerializer.Serialize(writer, entry, AuditJsonContext.Default.AuditEntry);
            writer.Flush();
            writer.Reset();
            buffer.GetSpan(1)[0] = (byte)'\n';
            buffer.Advance(1);
        }
        return buffer;
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

        // Wait for any in-flight SendAsync to finish its append, so the tail of the trail — the
        // most valuable part on shutdown — is on disk when DisposeAsync returns.
        await _lock.WaitAsync().ConfigureAwait(false);
        _lock.Release();
        _lock.Dispose();
    }

    private void LogDropped() =>
        Report("event=audit_forward action=send_dropped forwarder=NdjsonFile reason=disposed");

    /// <summary>Hands <paramref name="message"/> to <see cref="NdjsonFileAuditForwarderOptions.OnError"/>,
    /// or writes it to stderr when no callback is set. Never throws.</summary>
    private void Report(string message)
    {
        if (_onError is null)
        {
            Console.Error.WriteLine(message);
            return;
        }

#pragma warning disable CA1031, ERP022 // IAuditForwarder.SendAsync MUST NOT throw, even through a faulty callback.
        try
        {
            _onError(message);
        }
        catch
        {
            // The callback's own failure has nowhere safer to go.
        }
#pragma warning restore CA1031, ERP022
    }
}
