using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.AspNetCore;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers AI.Sentinel core services (detectors, pipeline, audit store, intervention engine).
    /// Also call app.UseAISentinel() to mount the dashboard.
    /// </summary>
    public static IServiceCollection AddAISentinel(
        this IServiceCollection services,
        Action<SentinelOptions>? configure = null)
    {
        AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services, configure);
        return services;
    }
}
