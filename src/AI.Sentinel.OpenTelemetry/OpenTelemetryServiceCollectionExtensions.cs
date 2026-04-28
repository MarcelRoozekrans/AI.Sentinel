using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.OpenTelemetry;

/// <summary>DI registration for <see cref="OpenTelemetryAuditForwarder"/>.</summary>
public static class OpenTelemetryServiceCollectionExtensions
{
    /// <summary>
    /// Registers an <see cref="OpenTelemetryAuditForwarder"/>. Does NOT wrap with
    /// <c>BufferingAuditForwarder</c> — the OTel SDK's <c>BatchLogRecordExportProcessor</c>
    /// already batches log records. Pulls <see cref="ILoggerFactory"/> from DI by default;
    /// callers may override via <paramref name="configure"/>.
    /// </summary>
    public static IServiceCollection AddSentinelOpenTelemetryForwarder(
        this IServiceCollection services,
        Action<OpenTelemetryAuditForwarderOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IAuditForwarder>(sp =>
        {
            var opts = new OpenTelemetryAuditForwarderOptions
            {
                LoggerFactory = sp.GetRequiredService<ILoggerFactory>(),
            };
            configure?.Invoke(opts);
            return new OpenTelemetryAuditForwarder(opts);
        });
        return services;
    }
}
