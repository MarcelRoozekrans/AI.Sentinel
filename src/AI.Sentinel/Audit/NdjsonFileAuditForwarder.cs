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
        _writer = new StreamWriter(_stream) { AutoFlush = false };
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
