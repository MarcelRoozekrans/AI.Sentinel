using AI.Sentinel.Audit;
using Azure.Monitor.Ingestion;

namespace AI.Sentinel.AzureSentinel;

/// <summary>Production wrapper that delegates to the real <see cref="LogsIngestionClient"/>.</summary>
internal sealed class LogsIngestionClientWrapper : ILogsIngestionClientWrapper
{
    private readonly LogsIngestionClient _client;

    public LogsIngestionClientWrapper(LogsIngestionClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public async Task UploadAsync(string ruleId, string streamName, IEnumerable<AuditEntry> entries, CancellationToken ct)
    {
        // The generic UploadAsync<T> overload serializes the IEnumerable<T> as JSON
        // and handles batching/retry/gzip internally.
        await _client.UploadAsync(ruleId, streamName, entries, options: null, cancellationToken: ct).ConfigureAwait(false);
    }
}
