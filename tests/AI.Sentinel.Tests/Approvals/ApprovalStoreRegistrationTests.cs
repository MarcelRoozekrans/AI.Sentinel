using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Approvals;

/// <summary>
/// The store DI hands out for <see cref="IApprovalStore"/> and <see cref="IApprovalAdmin"/> records approval
/// decisions whenever an <see cref="IAuditStore"/> is registered, whatever order the registrations come in.
/// </summary>
public sealed class ApprovalStoreRegistrationTests : IDisposable
{
    private const string Tool = "delete_database";
    private const string Policy = "approval:" + Tool;

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"approvals-di-{Guid.NewGuid():N}.db");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var path in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    private static void Gate(SentinelOptions opts) => opts.RequireApproval(Tool, _ => { });

    private static ApprovalContext MakeCtx()
    {
        using var doc = JsonDocument.Parse("""{"table":"orders"}""");
        return new ApprovalContext(Tool, doc.RootElement.Clone(), Justification: null);
    }

    private static async Task<string> OpenRequestAsync(IApprovalStore store)
    {
        var spec = new ApprovalSpec { PolicyName = Policy };
        var state = await store.EnsureRequestAsync(new TestCaller("caller"), spec, MakeCtx(), Ct);
        return Assert.IsType<ApprovalState.Pending>(state).RequestId;
    }

    private static async Task<List<AuditEntry>> ApprovedEntriesAsync(IAuditStore audit)
    {
        var entries = new List<AuditEntry>();
        await foreach (var e in audit.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, Ct))
        {
            if (string.Equals(e.PolicyCode, AuditEntryKinds.ApprovedPolicyCode, StringComparison.Ordinal))
            {
                entries.Add(e);
            }
        }
        return entries;
    }

    [Fact]
    public async Task HostResolvingAdminFromDi_Approve_WritesApproved()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(Gate);
        await using var sp = services.BuildServiceProvider();

        var requestId = await OpenRequestAsync(sp.GetRequiredService<IApprovalStore>());
        await sp.GetRequiredService<IApprovalAdmin>().ApproveAsync(requestId, "approver", null, Ct);

        var entry = Assert.Single(await ApprovedEntriesAsync(sp.GetRequiredService<IAuditStore>()));
        Assert.EndsWith(AuditEntryKinds.ApprovalRequestMarker + requestId, entry.Summary, StringComparison.Ordinal);
    }

    /// <summary>
    /// With an approval binding AddAISentinel registers the in-memory store when none is registered yet, so a backend
    /// goes after it only when that call has no binding, as in a host that only approves through its own UI.
    /// </summary>
    private static void AddSentinel(IServiceCollection services, Order order)
    {
        if (order == Order.StoreBeforeSentinel) services.AddAISentinel(Gate);
        else services.AddAISentinel();
    }

    public enum Order
    {
        StoreBeforeSentinel,
        StoreAfterSentinel,
    }

    [Theory]
    [InlineData(Order.StoreBeforeSentinel)]
    [InlineData(Order.StoreAfterSentinel)]
    public async Task SqliteStore_AnyRegistrationOrder_AuditStoreReplacedAfter_DiAdminApprovalIsAudited(Order order)
    {
        var services = new ServiceCollection();
        if (order == Order.StoreBeforeSentinel) services.AddSentinelSqliteApprovalStore(o => o.DatabasePath = _dbPath);
        AddSentinel(services, order);
        if (order == Order.StoreAfterSentinel) services.AddSentinelSqliteApprovalStore(o => o.DatabasePath = _dbPath);

        // Replaces the ring buffer AddAISentinel registers, as AddSentinelSqlite and the CLIs do.
        using var audit = new RingBufferAuditStore();
        services.AddSingleton<IAuditStore>(audit);
        await using var sp = services.BuildServiceProvider();

        var requestId = await OpenRequestAsync(sp.GetRequiredService<IApprovalStore>());
        await sp.GetRequiredService<IApprovalAdmin>().ApproveAsync(requestId, "approver", null, Ct);

        Assert.Single(await ApprovedEntriesAsync(audit));
    }

    [Theory]
    [InlineData(Order.StoreBeforeSentinel)]
    [InlineData(Order.StoreAfterSentinel)]
    public async Task EntraPimStore_AnyRegistrationOrder_DiStoreIsTheAuditingWrapper(Order order)
    {
        var services = new ServiceCollection();
        if (order == Order.StoreBeforeSentinel) services.AddSentinelEntraPimApprovalStore(o => o.TenantId = "tenant");
        AddSentinel(services, order);
        if (order == Order.StoreAfterSentinel) services.AddSentinelEntraPimApprovalStore(o => o.TenantId = "tenant");
        await using var sp = services.BuildServiceProvider();

        var store = sp.GetRequiredService<IApprovalStore>();
        Assert.IsType<AuditingApprovalStore>(store);
        Assert.Null(sp.GetService<IApprovalAdmin>());
        Assert.Same(store, ApprovalStoreAuditing.Resolve(sp));
    }

    [Fact]
    public async Task EveryConsumerPath_SharesOneWrapper_AndOneApproveWritesOneEntry()
    {
        var services = new ServiceCollection();
        services.AddSentinelSqliteApprovalStore(o => o.DatabasePath = _dbPath);
        services.AddAISentinel(Gate);
        await using var sp = services.BuildServiceProvider();

        var store = sp.GetRequiredService<IApprovalStore>();
        var admin = sp.GetRequiredService<IApprovalAdmin>();
        var resolved = ApprovalStoreAuditing.Resolve(sp);
        Assert.Same(store, admin);
        Assert.Same(store, resolved);
        Assert.IsType<AuditingApprovalAdminStore>(store);

        // The guard opens the request, the host approves through DI, the guard and a waiter see the grant.
        var guard = sp.GetRequiredService<IToolCallGuard>();
        var caller = new TestCaller("caller");
        var first = await guard.AuthorizeAsync(caller, Tool, MakeCtx().Args, Ct);
        var requestId = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(first).RequestId;
        await admin.ApproveAsync(requestId, "approver", null, Ct);
        await admin.ApproveAsync(requestId, "approver", null, Ct);
        Assert.IsType<AuthorizationDecision.AllowDecision>(await guard.AuthorizeAsync(caller, Tool, MakeCtx().Args, Ct));
        await resolved!.WaitForDecisionAsync(requestId, TimeSpan.FromSeconds(1), Ct);

        Assert.Single(await ApprovedEntriesAsync(sp.GetRequiredService<IAuditStore>()));
    }

    [Fact]
    public async Task AddAISentinel_AlwaysRegistersAnAuditStore_SoTheAutoRegisteredStoreIsWrapped()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(Gate);
        await using var sp = services.BuildServiceProvider();

        Assert.NotNull(sp.GetService<IAuditStore>());
        Assert.IsType<AuditingApprovalAdminStore>(sp.GetRequiredService<IApprovalStore>());
    }

    [Fact]
    public async Task NoAuditStore_NamedPipelineOnly_DiHandsOutTheInnerStore()
    {
        // Only the unnamed AddAISentinel registers an audit store.
        var services = new ServiceCollection();
        services.AddAISentinel("strict", Gate);
        await using var sp = services.BuildServiceProvider();

        Assert.Null(sp.GetService<IAuditStore>());
        var store = sp.GetRequiredService<IApprovalStore>();
        Assert.IsType<InMemoryApprovalStore>(store);
        Assert.Same(store, sp.GetRequiredService<IApprovalAdmin>());
        Assert.Same(store, ApprovalStoreAuditing.Resolve(sp));
    }

    [Fact]
    public async Task NoAuditStore_SqliteAlone_DiHandsOutTheConcreteStore()
    {
        var services = new ServiceCollection();
        services.AddSentinelSqliteApprovalStore(o => o.DatabasePath = _dbPath);
        await using var sp = services.BuildServiceProvider();

        var concrete = sp.GetRequiredService<SqliteApprovalStore>();
        Assert.Same(concrete, sp.GetRequiredService<IApprovalStore>());
        Assert.Same(concrete, sp.GetRequiredService<IApprovalAdmin>());
    }

    private sealed class TestCaller(string id) : ISecurityContext
    {
        public string Id { get; } = id;
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }
}
