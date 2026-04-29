using AI.Sentinel.Approvals;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Approvals.EntraPim.Tests;

public class EntraPimServiceCollectionExtensionsTests
{
    private const string FakeTenantId = "00000000-0000-0000-0000-000000000000";

    [Fact]
    public void AddSentinelEntraPimApprovalStore_RegistersIApprovalStoreAsEntraPim()
    {
        var services = new ServiceCollection();
        services.AddSentinelEntraPimApprovalStore(opts => opts.TenantId = FakeTenantId);

        using var sp = services.BuildServiceProvider();
        var store = sp.GetService<IApprovalStore>();

        // Resolution must succeed even though no real TokenCredential is registered —
        // the GraphServiceClient is constructed lazily and never actually called by
        // the smoke test. This guarantees the wiring works in test environments
        // without external Azure credentials.
        Assert.NotNull(store);
        Assert.IsType<EntraPimApprovalStore>(store);
    }

    [Fact]
    public void AddSentinelEntraPimApprovalStore_MissingTenantId_ThrowsAtRegistration()
    {
        var services = new ServiceCollection();

        // Validation runs eagerly inside the extension method (mirroring AddSentinelSqliteStore),
        // so misconfiguration surfaces where it was authored — not on first resolve.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddSentinelEntraPimApprovalStore(_ => { /* TenantId not set */ }));
        Assert.Contains("TenantId", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddSentinelEntraPimApprovalStore_RegistersAsSingleton()
    {
        var services = new ServiceCollection();
        services.AddSentinelEntraPimApprovalStore(opts => opts.TenantId = FakeTenantId);

        using var sp = services.BuildServiceProvider();
        var s1 = sp.GetRequiredService<IApprovalStore>();
        var s2 = sp.GetRequiredService<IApprovalStore>();

        Assert.Same(s1, s2);
    }

    [Fact]
    public void AddSentinelEntraPimApprovalStore_NullServices_Throws()
    {
        IServiceCollection services = null!;
        Assert.Throws<ArgumentNullException>(() =>
            services.AddSentinelEntraPimApprovalStore(opts => opts.TenantId = FakeTenantId));
    }

    [Fact]
    public void AddSentinelEntraPimApprovalStore_NullConfigure_Throws()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddSentinelEntraPimApprovalStore(configure: null!));
    }

    [Fact]
    public void AddSentinelEntraPimApprovalStore_DuplicateRegistration_Throws()
    {
        // Approval-store backends are exclusive: silently overwriting a prior registration
        // (e.g. AddSentinelSqliteStore + AddSentinelEntraPimApprovalStore) is almost always
        // a wiring bug. The guard fails fast with an operator-actionable message instead.
        var services = new ServiceCollection();
        services.AddSingleton<IApprovalStore>(new InMemoryApprovalStore());

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddSentinelEntraPimApprovalStore(opts => opts.TenantId = FakeTenantId));
        Assert.Contains("already registered", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
