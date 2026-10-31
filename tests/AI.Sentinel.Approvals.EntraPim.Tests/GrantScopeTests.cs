using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Notifications;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace AI.Sentinel.Approvals.EntraPim.Tests;

public class GrantScopeTests
{
    private const string FakeTenantId = "00000000-0000-0000-0000-000000000000";

    [Fact]
    public void CallScopedRule_OnEntraPimStore_FailsWhenTheGuardIsResolved()
    {
        using var sp = Build(ApprovalGrantScope.Call);

        var ex = Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IToolCallGuard>());
        Assert.Contains("GrantScope.Call", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Entra PIM", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GrantScopeCall_RejectedWithNotifier()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new ApprovalNotifierSettings(
            new Uri("http://127.0.0.1:9/"), new Dictionary<string, string>(StringComparer.Ordinal), false, null));
        services.AddSingleton<IGraphRoleClient>(new NoopGraphRoleClient());
        services.AddSentinelEntraPimApprovalStore(o => o.TenantId = FakeTenantId);
        services.AddAISentinel(o => o.RequireApproval("Bash", s => s.GrantScope = ApprovalGrantScope.Call));
        using var sp = services.BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IToolCallGuard>());
        Assert.Contains("GrantScope.Call", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Entra PIM", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RuleScopedRule_OnEntraPimStore_ResolvesTheGuard()
    {
        using var sp = Build(ApprovalGrantScope.Rule);

        Assert.NotNull(sp.GetRequiredService<IToolCallGuard>());
    }

    [Fact]
    public void CallScopedRule_OnEntraPimStoreRegisteredDirectly_FailsWhenTheGuardIsResolved()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IApprovalStore>(
            new EntraPimApprovalStore(new NoopGraphRoleClient(), new EntraPimOptions { TenantId = FakeTenantId }));
        services.AddAISentinel(o => o.RequireApproval("Bash", s => s.GrantScope = ApprovalGrantScope.Call));
        using var sp = services.BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IToolCallGuard>());
        Assert.Contains("Entra PIM", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CallScopedRule_AfterTheEntraPimStoreWasSwappedForInMemory_ResolvesTheGuard()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IGraphRoleClient>(new NoopGraphRoleClient());
        services.AddSentinelEntraPimApprovalStore(o => o.TenantId = FakeTenantId);
        services.RemoveAll<IApprovalStore>();
        services.AddSingleton<IApprovalStore, InMemoryApprovalStore>();
        services.AddAISentinel(o => o.RequireApproval("Bash", s => s.GrantScope = ApprovalGrantScope.Call));
        using var sp = services.BuildServiceProvider();

        Assert.NotNull(sp.GetRequiredService<IToolCallGuard>());
    }

    [Fact]
    public void CallScopedRule_OnTheDefaultInMemoryStore_ResolvesTheGuard()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o => o.RequireApproval("Bash", s => s.GrantScope = ApprovalGrantScope.Call));
        using var sp = services.BuildServiceProvider();

        Assert.NotNull(sp.GetRequiredService<IToolCallGuard>());
    }

    private static ServiceProvider Build(ApprovalGrantScope scope)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IGraphRoleClient>(new NoopGraphRoleClient());
        services.AddSentinelEntraPimApprovalStore(o => o.TenantId = FakeTenantId);
        services.AddAISentinel(o => o.RequireApproval("Bash", s => s.GrantScope = scope));
        return services.BuildServiceProvider();
    }

    private sealed class NoopGraphRoleClient : IGraphRoleClient
    {
        public ValueTask<string?> ResolveRoleIdAsync(string displayName, CancellationToken ct) => new((string?)null);

        public ValueTask<RoleScheduleSnapshot?> GetActiveAssignmentAsync(string principalId, string roleId, CancellationToken ct) =>
            new((RoleScheduleSnapshot?)null);

        public ValueTask<bool> IsEligibleAsync(string principalId, string roleId, CancellationToken ct) => new(false);

        public ValueTask<PendingRoleRequest?> GetPendingActivationRequestAsync(
            string principalId, string roleId, CancellationToken ct) => new((PendingRoleRequest?)null);

        public ValueTask<string> CreateActivationRequestAsync(
            string principalId, string roleId, TimeSpan duration, string justification, CancellationToken ct) => new("req");

        public ValueTask<RoleRequestSnapshot> GetRequestStatusAsync(string requestId, CancellationToken ct) =>
            new(new RoleRequestSnapshot("Failed", "noop"));
    }
}
