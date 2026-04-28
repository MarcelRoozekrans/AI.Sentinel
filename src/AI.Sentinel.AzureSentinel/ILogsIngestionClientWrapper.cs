using AI.Sentinel.Audit;

namespace AI.Sentinel.AzureSentinel;

/// <summary>Test seam over <see cref="Azure.Monitor.Ingestion.LogsIngestionClient"/>. Production impl simply delegates; tests stub this directly.</summary>
internal interface ILogsIngestionClientWrapper
{
    Task UploadAsync(string ruleId, string streamName, IEnumerable<AuditEntry> entries, CancellationToken ct);
}
