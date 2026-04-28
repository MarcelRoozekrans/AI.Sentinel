using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.OpenTelemetry;

/// <summary>
/// Vendor-neutral audit forwarder that emits each <see cref="AuditEntry"/> as an
/// OpenTelemetry <c>LogRecord</c> via <see cref="ILogger"/>. Batching and exporter
/// routing are handled by the OTel SDK's <c>BatchLogRecordExportProcessor</c> — DO NOT
/// wrap this forwarder with <c>BufferingAuditForwarder&lt;T&gt;</c>.
/// </summary>
public sealed class OpenTelemetryAuditForwarder : IAuditForwarder
{
    private readonly ILogger _logger;

    public OpenTelemetryAuditForwarder(OpenTelemetryAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var factory = options.LoggerFactory
            ?? throw new ArgumentException("LoggerFactory must be set.", nameof(options));
        _logger = factory.CreateLogger(options.CategoryName);
    }

    /// <inheritdoc />
    public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(batch);
        if (batch.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        for (var i = 0; i < batch.Count; i++)
        {
            var entry = batch[i];
            var level = MapSeverity(entry.Severity);
            using (_logger.BeginScope(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["audit.id"] = entry.Id,
                ["audit.detector_id"] = entry.DetectorId,
                ["audit.severity"] = entry.Severity.ToString(),
                ["audit.hash"] = entry.Hash,
                ["audit.previous_hash"] = entry.PreviousHash,
                ["audit.timestamp"] = entry.Timestamp.ToString("O", CultureInfo.InvariantCulture),
            }))
            {
#pragma warning disable CA1848 // LoggerMessage source-gen would couple emission shape to a static template; per-entry attributes flow via scope.
                _logger.Log(level, "{Summary}", entry.Summary);
#pragma warning restore CA1848
            }
        }
        return ValueTask.CompletedTask;
    }

    private static LogLevel MapSeverity(Severity sev) => sev switch
    {
        Severity.Critical => LogLevel.Critical,
        Severity.High => LogLevel.Error,
        Severity.Medium => LogLevel.Warning,
        Severity.Low => LogLevel.Information,
        _ => LogLevel.Debug,
    };
}
