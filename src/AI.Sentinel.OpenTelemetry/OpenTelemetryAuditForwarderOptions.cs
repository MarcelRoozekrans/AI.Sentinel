using Microsoft.Extensions.Logging;

namespace AI.Sentinel.OpenTelemetry;

/// <summary>Configuration for <see cref="OpenTelemetryAuditForwarder"/>.</summary>
public sealed class OpenTelemetryAuditForwarderOptions
{
    /// <summary>Logger factory used to create the audit logger. If null, the forwarder pulls one from DI at registration time.</summary>
    public ILoggerFactory? LoggerFactory { get; set; }

    /// <summary>Logger category name. Defaults to <c>AI.Sentinel.Audit</c>.</summary>
    public string CategoryName { get; set; } = "AI.Sentinel.Audit";
}
