using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using Xunit;

namespace AI.Sentinel.OpenTelemetry.Tests;

public sealed class OpenTelemetryAuditForwarderTests
{
    private static AuditEntry Make(string id, Severity sev = Severity.High) =>
        new(id, DateTimeOffset.UtcNow, $"h-{id}", "prev", sev, "SEC-01", $"summary-{id}");

    [Fact]
    public async Task SendAsync_EmitsOneLogRecordPerEntry()
    {
        var records = new List<LogRecord>();
        using var loggerFactory = LoggerFactory.Create(b => b
            .SetMinimumLevel(LogLevel.Trace)
            .AddOpenTelemetry(o =>
            {
                o.IncludeScopes = true;
                o.AddInMemoryExporter(records);
            }));

        var f = new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions { LoggerFactory = loggerFactory });
        await f.SendAsync(new[] { Make("e1"), Make("e2"), Make("e3") }, default);

        // Force flush by disposing the factory (ends the OTel logger provider).
        loggerFactory.Dispose();

        Assert.Equal(3, records.Count);
    }

    [Theory]
    [InlineData(Severity.Critical, LogLevel.Critical)]
    [InlineData(Severity.High, LogLevel.Error)]
    [InlineData(Severity.Medium, LogLevel.Warning)]
    [InlineData(Severity.Low, LogLevel.Information)]
    [InlineData(Severity.None, LogLevel.Debug)]
    public async Task SendAsync_SeverityMapsToLogLevel(Severity sev, LogLevel expected)
    {
        var records = new List<LogRecord>();
        using var loggerFactory = LoggerFactory.Create(b => b
            .SetMinimumLevel(LogLevel.Trace)
            .AddOpenTelemetry(o =>
            {
                o.IncludeScopes = true;
                o.AddInMemoryExporter(records);
            }));

        var f = new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions { LoggerFactory = loggerFactory });
        await f.SendAsync(new[] { Make("e1", sev) }, default);

        loggerFactory.Dispose();
        Assert.Single(records);
        Assert.Equal(expected, records[0].LogLevel);
    }

    [Fact]
    public async Task SendAsync_AuditEntryFieldsLiftedAsAttributes()
    {
        var records = new List<LogRecord>();
        using var loggerFactory = LoggerFactory.Create(b => b
            .SetMinimumLevel(LogLevel.Trace)
            .AddOpenTelemetry(o =>
            {
                o.IncludeScopes = true;
                o.AddInMemoryExporter(records);
            }));

        var f = new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions { LoggerFactory = loggerFactory });
        await f.SendAsync(new[] { Make("e1") }, default);
        loggerFactory.Dispose();

        Assert.Single(records);
        var rec = records[0];

        // Scope contents are surfaced via ForEachScope when IncludeScopes=true.
        // LogRecordScope itself enumerates KeyValuePair<string, object?>.
        var scopeAttrs = new Dictionary<string, object?>(StringComparer.Ordinal);
        rec.ForEachScope<object?>(
            (scope, _) =>
            {
                foreach (var kv in scope)
                {
                    scopeAttrs[kv.Key] = kv.Value;
                }
            },
            null);

        Assert.Equal("e1", scopeAttrs["audit.id"]);
        Assert.Equal("SEC-01", scopeAttrs["audit.detector_id"]);
        Assert.Equal("h-e1", scopeAttrs["audit.hash"]);
        Assert.Equal("prev", scopeAttrs["audit.previous_hash"]);
    }

    [Fact]
    public async Task SendAsync_EmptyBatch_NoLogRecords()
    {
        var records = new List<LogRecord>();
        using var loggerFactory = LoggerFactory.Create(b => b
            .SetMinimumLevel(LogLevel.Trace)
            .AddOpenTelemetry(o => o.AddInMemoryExporter(records)));

        var f = new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions { LoggerFactory = loggerFactory });
        await f.SendAsync(Array.Empty<AuditEntry>(), default);
        loggerFactory.Dispose();

        Assert.Empty(records);
    }

    [Fact]
    public void Construction_NullLoggerFactory_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new OpenTelemetryAuditForwarder(new OpenTelemetryAuditForwarderOptions()));
    }
}
