using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Sqlite;

/// <summary>DI registration for <see cref="SqliteAuditStore"/>.</summary>
public static class SqliteAuditStoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="SqliteAuditStore"/> as the <see cref="IAuditStore"/>.
    /// Last-registration-wins for <see cref="IAuditStore"/>; callers that need to
    /// replace a previously registered store should call this after the prior
    /// registration.
    /// </summary>
    public static IServiceCollection AddSentinelSqliteStore(
        this IServiceCollection services,
        Action<SqliteAuditStoreOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var opts = new SqliteAuditStoreOptions();
        configure(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAuditStore>(_ => new SqliteAuditStore(opts));
        return services;
    }
}
