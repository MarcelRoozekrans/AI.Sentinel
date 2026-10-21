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
        // and its lock file if they are missing and prove both are writable. Every send needs both, so a
        // directory that refuses the lock file must fail here, not on every batch. The files are opened
        // per batch from here on, so no handle is held between sends and other processes can append too.
        ProbeWritable(_filePath, FileMode.Append, FileAccess.Write, DataFileShare);
        ProbeWritable(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    /// <summary>Opens and closes <paramref name="path"/>, creating it if missing. A sharing violation counts as
    /// success: another writer or a reader holds the file right now, and the operating system checks access
    /// before sharing, so the file exists and this process may write it.</summary>
    private static void ProbeWritable(string path, FileMode mode, FileAccess access, FileShare share)
    {
        try
        {
            using (new FileStream(path, mode, access, share, bufferSize: 0))
            {
            }
        }
        catch (IOException ex) when (IsSharingViolation(ex))
        {
            // Busy, not broken.
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
            Report($"event=audit_forward action=send_error forwarder=NdjsonFile error={ex.GetType().Name} inner={ex.InnerException?.GetType().Name ?? "none"}");
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
        // One deadline for the whole append: the lock file and, under it, the data file.
        var deadline = Environment.TickCount64 + (long)_lockTimeout.TotalMilliseconds;
        var fileLock = await OpenWithRetryAsync(isLock: true, deadline, ct).ConfigureAwait(false);
        await using (fileLock.ConfigureAwait(false))
        {
            // On Windows a reader that opened the file without FileShare.Write blocks this open for as
            // long as it keeps the file open; retry it like the lock.
            var stream = await OpenWithRetryAsync(isLock: false, deadline, ct).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                // FileMode.Append positioned the stream at the end as of the open, which is the true end:
                // every writer appends only while it holds the lock file.
                var start = stream.Position;
                try
                {
                    // Not cancellable once the lock is held: the token only bounds the waits.
                    await stream.WriteAsync(payload, CancellationToken.None).ConfigureAwait(false);
                    await stream.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    // A failed write (disk full, I/O error) may have written part of the batch. Cut the
                    // file back so the next writer never appends after a torn line.
                    TryTruncate(stream, start);
                    throw;
                }
            }
        }
    }

    private static void TryTruncate(FileStream stream, long length)
    {
#pragma warning disable CA1031, ERP022 // Best effort: the write failure is what gets reported.
        try
        {
            stream.SetLength(length);
        }
        catch
        {
            // Nothing safer to do; the original exception is rethrown by the caller.
        }
#pragma warning restore CA1031, ERP022
    }

    /// <summary>Opens the lock file exclusively (<paramref name="isLock"/>) or the data file for appending, retrying
    /// with a capped exponential backoff while another writer or a reader holds it, until <paramref name="deadline"/>.
    /// Only a sharing or lock violation is retried; any other failure is thrown at once. The lock is released by
    /// disposing the returned stream, and by the operating system when a writer process dies.</summary>
    private async Task<FileStream> OpenWithRetryAsync(bool isLock, long deadline, CancellationToken ct)
    {
        var backoff = TimeSpan.FromMilliseconds(1);
        while (true)
        {
            try
            {
                // bufferSize 0: no FileStream buffer, so the batch reaches the OS as the single write the
                // caller makes. FileShare.None on the lock file is the lock: Windows refuses a second open
                // with a sharing violation, and .NET on Unix takes an exclusive flock on the handle.
                return isLock
                    ? new FileStream(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, bufferSize: 0)
                    : new FileStream(_filePath, FileMode.Append, FileAccess.Write, DataFileShare, bufferSize: 0, FileOptions.Asynchronous);
            }
            catch (IOException ex) when (IsSharingViolation(ex))
            {
                var remaining = deadline - Environment.TickCount64;
                if (remaining <= 0)
                {
                    throw new TimeoutException(
                        $"Could not open '{(isLock ? _lockPath : _filePath)}' within {_lockTimeout}; another process holds it.", ex);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(backoff.TotalMilliseconds, remaining)), ct).ConfigureAwait(false);
                backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxLockBackoff.Ticks));
            }
        }
    }

    /// <summary>True when <paramref name="ex"/> means another handle holds the file, and nothing else is wrong.
    /// Windows reports ERROR_SHARING_VIOLATION or ERROR_LOCK_VIOLATION. .NET on Unix reports a failed
    /// non-blocking <c>flock</c> as an <see cref="IOException"/> whose HResult is the raw errno EWOULDBLOCK:
    /// 11 on Linux, 35 on macOS and FreeBSD.</summary>
    private static bool IsSharingViolation(IOException ex)
    {
        if (OperatingSystem.IsWindows())
        {
            return ex.HResult is unchecked((int)0x80070020) or unchecked((int)0x80070021);
        }
        if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())
        {
            return ex.HResult == 11;
        }
        return ex.HResult == 35;
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
