using AI.Sentinel.Approvals;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Approvals.Sqlite.Tests;

public sealed class SqliteApprovalStoreServiceCollectionExtensionsTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"approvals-di-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
        if (File.Exists(_dbPath + "-wal")) File.Delete(_dbPath + "-wal");
        if (File.Exists(_dbPath + "-shm")) File.Delete(_dbPath + "-shm");
    }

    [Fact]
    public async Task AddSentinelSqliteApprovalStore_RegistersIApprovalStore()
    {
        var services = new ServiceCollection();
        services.AddSentinelSqliteApprovalStore(opts => opts.DatabasePath = _dbPath);

        await using var sp = services.BuildServiceProvider();
        var store = sp.GetService<IApprovalStore>();

        Assert.NotNull(store);
        Assert.IsType<SqliteApprovalStore>(store);
    }

    [Fact]
    public async Task AddSentinelSqliteApprovalStore_RegistersIApprovalAdminAsSameInstance()
    {
        var services = new ServiceCollection();
        services.AddSentinelSqliteApprovalStore(opts => opts.DatabasePath = _dbPath);

        await using var sp = services.BuildServiceProvider();
        var store = sp.GetRequiredService<IApprovalStore>();
        var admin = sp.GetRequiredService<IApprovalAdmin>();

        Assert.Same(store, admin);
    }

    [Fact]
    public void AddSentinelSqliteApprovalStore_MissingDatabasePath_ThrowsAtRegistration()
    {
        var services = new ServiceCollection();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddSentinelSqliteApprovalStore(opts => { /* DatabasePath not set */ }));
        Assert.Contains("DatabasePath", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddSentinelSqliteApprovalStore_DuplicateRegistration_Throws()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IApprovalStore>(new InMemoryApprovalStore());

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddSentinelSqliteApprovalStore(opts => opts.DatabasePath = _dbPath));
        Assert.Contains("already registered", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AddSentinelSqliteApprovalStore_NullArgs_Throw()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ((IServiceCollection)null!).AddSentinelSqliteApprovalStore(_ => { }));

        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddSentinelSqliteApprovalStore(null!));
    }
}
