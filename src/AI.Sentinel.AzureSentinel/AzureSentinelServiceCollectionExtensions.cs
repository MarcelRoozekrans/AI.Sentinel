using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.AzureSentinel;

/// <summary>DI registration for <see cref="AzureSentinelAuditForwarder"/>.</summary>
public static class AzureSentinelServiceCollectionExtensions
{
    /// <summary>
    /// Registers an <see cref="AzureSentinelAuditForwarder"/> wrapped with
    /// <see cref="BufferingAuditForwarder{TInner}"/> (defaults: batch=100, interval=5s).
    /// Per-entry HTTP roundtrips are unworkable; buffering is mandatory for SIEM ingestion.
    /// </summary>
    public static IServiceCollection AddSentinelAzureSentinelForwarder(
        this IServiceCollection services,
        Action<AzureSentinelAuditForwarderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var opts = new AzureSentinelAuditForwarderOptions();
        configure(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAuditForwarder>(_ =>
            new BufferingAuditForwarder<AzureSentinelAuditForwarder>(
                new AzureSentinelAuditForwarder(opts),
                new BufferingAuditForwarderOptions()));
        return services;
    }
}
