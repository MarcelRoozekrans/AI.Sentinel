using AI.Sentinel.Audit;
using AI.Sentinel.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

public class SqliteAuditStoreLifetimeTests
{
    [Fact]
    public void AddSentinelSqliteStore_RegistersAsSingleton()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"sentinel-{Guid.NewGuid():N}.db");
        try
        {
            var services = new ServiceCollection();
            services.AddSentinelSqliteStore(opts => opts.DatabasePath = dbPath);
            var descriptors = services.Where(d => d.ServiceType == typeof(IAuditStore)).ToList();
            Assert.Single(descriptors);
            Assert.Equal(ServiceLifetime.Singleton, descriptors[0].Lifetime);
        }
        finally
        {
            try { File.Delete(dbPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    [Fact]
    public async Task AddSentinelSqliteStore_AfterAddAISentinel_LastWinsAtServiceProviderResolution()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"sentinel-{Guid.NewGuid():N}.db");
        try
        {
            var services = new ServiceCollection();
            services.AddAISentinel(opts => { });            // registers RingBufferAuditStore
            services.AddSentinelSqliteStore(opts => opts.DatabasePath = dbPath);  // adds SqliteAuditStore

            // SqliteAuditStore is IAsyncDisposable only — the provider must be disposed async.
            await using var sp = services.BuildServiceProvider();
            // Microsoft.Extensions.DI: GetService<T>() returns the LAST registered impl
            var resolved = sp.GetRequiredService<IAuditStore>();
            Assert.IsType<SqliteAuditStore>(resolved);
        }
        finally
        {
            try { File.Delete(dbPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
