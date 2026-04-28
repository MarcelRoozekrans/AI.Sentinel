using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Audit;

/// <summary>DI extensions for registering AI.Sentinel audit forwarders.</summary>
public static class AuditForwarderServiceCollectionExtensions
{
    /// <summary>Registers an <see cref="NdjsonFileAuditForwarder"/>. Direct file append; no buffering applied (file I/O is already fast).</summary>
    public static IServiceCollection AddSentinelNdjsonFileForwarder(
        this IServiceCollection services,
        Action<NdjsonFileAuditForwarderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var opts = new NdjsonFileAuditForwarderOptions();
        configure(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAuditForwarder>(_ => new NdjsonFileAuditForwarder(opts));
        return services;
    }
}
