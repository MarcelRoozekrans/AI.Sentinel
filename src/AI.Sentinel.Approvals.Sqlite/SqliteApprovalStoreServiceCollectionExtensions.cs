using AI.Sentinel.Approvals;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AI.Sentinel.Approvals.Sqlite;

/// <summary>DI extensions for <see cref="SqliteApprovalStore"/>.</summary>
public static class SqliteApprovalStoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="SqliteApprovalStore"/> as the <see cref="IApprovalStore"/>
    /// (and <see cref="IApprovalAdmin"/>) for AI.Sentinel approval gates. State persists
    /// across process restarts via a SQLite database file — required for CLI deployments
    /// where each invocation is a fresh process.
    /// </summary>
    /// <remarks>
    /// Throws <see cref="InvalidOperationException"/> at registration time if an
    /// <see cref="IApprovalStore"/> is already registered — approval-store backends
    /// are exclusive. Remove the existing registration first.
    /// </remarks>
    public static IServiceCollection AddSentinelSqliteApprovalStore(
        this IServiceCollection services,
        Action<SqliteApprovalStoreOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        if (services.Any(sd => sd.ServiceType == typeof(IApprovalStore)))
        {
            throw new InvalidOperationException(
                "An IApprovalStore is already registered. Approval-store backends are exclusive — " +
                "remove the existing registration before wiring AddSentinelSqliteApprovalStore.");
        }

        var opts = BuildOptions(configure);
        services.AddSingleton(opts);

        services.AddSingleton<SqliteApprovalStore>(sp =>
            new SqliteApprovalStore(sp.GetRequiredService<SqliteApprovalStoreOptions>()));

        services.AddSingleton<IApprovalStore>(sp => sp.GetRequiredService<SqliteApprovalStore>());
        services.AddSingleton<IApprovalAdmin>(sp => sp.GetRequiredService<SqliteApprovalStore>());

        return services;
    }

    private static SqliteApprovalStoreOptions BuildOptions(Action<SqliteApprovalStoreOptions> configure)
    {
        var opts = new SqliteApprovalStoreOptions { DatabasePath = "" };
        configure(opts);
        if (string.IsNullOrWhiteSpace(opts.DatabasePath))
        {
            throw new InvalidOperationException(
                "SqliteApprovalStoreOptions.DatabasePath must be configured (path to the .db file).");
        }
        return opts;
    }
}
