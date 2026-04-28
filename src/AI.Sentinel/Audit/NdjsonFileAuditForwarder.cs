using System.Text.Json;

namespace AI.Sentinel.Audit;

/// <summary>Audit forwarder that appends each entry as a JSON line to a local NDJSON file. Operators ship the file via Filebeat / Vector / Fluent Bit etc. Direct file append; no buffering needed (file I/O is microsecond-scale).</summary>
public sealed class NdjsonFileAuditForwarder : IAuditForwarder, IAsyncDisposable
{
    private readonly FileStream _stream;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _lock = new(1, 1);

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

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
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
            // Surface IO / serialization failures via stderr; never propagate.
            // Matches the swallow-and-log posture of BufferingAuditForwarder.FlushAsync
            // and AzureSentinelAuditForwarder.SendAsync.
            Console.Error.WriteLine($"event=audit_forward action=send_error forwarder=NdjsonFile error={ex.GetType().Name}");
        }
#pragma warning restore CA1031
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _writer.DisposeAsync().ConfigureAwait(false);
        await _stream.DisposeAsync().ConfigureAwait(false);
        _lock.Dispose();
    }
}
