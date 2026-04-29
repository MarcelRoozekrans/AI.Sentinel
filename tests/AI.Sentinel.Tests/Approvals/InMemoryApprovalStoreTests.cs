using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using System.Text.Json;
using Xunit;

namespace AI.Sentinel.Tests.Approvals;

public class InMemoryApprovalStoreTests
{
    private static ApprovalSpec MakeSpec(string policy = "p", TimeSpan? grant = null) =>
        new() { PolicyName = policy, GrantDuration = grant ?? TimeSpan.FromMinutes(15) };

    private static ApprovalContext MakeCtx() => new("delete_database", default, null);

    private static ISecurityContext MakeCaller(string id = "alice") =>
        new TestSecurityContext(id);

    // Local fake for ISecurityContext. Note: spec showed Roles as IReadOnlyList<string>,
    // but the real interface uses IReadOnlySet<string> + IReadOnlyDictionary<string,string> Claims —
    // so we match the actual interface shape (otherwise the file would not compile).
    private sealed class TestSecurityContext(string id) : ISecurityContext
    {
        public string Id { get; } = id;
#pragma warning disable HLQ001 // Boxing on init is fine for a test helper
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
#pragma warning restore HLQ001
    }

    [Fact]
    public async Task EnsureRequest_FirstCall_ReturnsPending()
    {
        var store = new InMemoryApprovalStore();
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Pending>(state);
    }

    [Fact]
    public async Task EnsureRequest_RepeatedCall_DedupesByCallerAndPolicy()
    {
        var store = new InMemoryApprovalStore();
        var first = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var second = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Pending>(second);
        Assert.Equal(first.RequestId, ((ApprovalState.Pending)second).RequestId);
    }

    [Fact]
    public async Task ApproveAsync_TransitionsToActive()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        await store.ApproveAsync(pending.RequestId, "approver", note: null, default);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Active>(state);
    }

    [Fact]
    public async Task DenyAsync_TransitionsToDenied()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        await store.DenyAsync(pending.RequestId, "approver", "no", default);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Denied>(state);
    }

    [Fact]
    public async Task ActiveGrant_AfterExpiry_ReturnsDenied()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            MakeCaller(),
            MakeSpec(grant: TimeSpan.FromMilliseconds(50)),
            MakeCtx(),
            default);
        await store.ApproveAsync(pending.RequestId, "a", null, default);
        await Task.Delay(150);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Denied>(state);
    }

    [Fact]
    public async Task WaitForDecision_TriggersOnApprove()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var waitTask = store.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(2), default).AsTask();
        await Task.Delay(50);
        await store.ApproveAsync(pending.RequestId, "a", null, default);
        var result = await waitTask;
        Assert.IsType<ApprovalState.Active>(result);
    }

    [Fact]
    public async Task ListPending_ReturnsOnlyPendingRequests()
    {
        var store = new InMemoryApprovalStore();
        var p1 = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller("a"), MakeSpec("p1"), MakeCtx(), default);
        await store.EnsureRequestAsync(MakeCaller("b"), MakeSpec("p2"), MakeCtx(), default);
        await store.ApproveAsync(p1.RequestId, "a", null, default);

        var pending = new List<PendingRequest>();
        await foreach (var r in store.ListPendingAsync(default)) pending.Add(r);
        Assert.Single(pending);
        Assert.Equal("p2", pending[0].PolicyName);
    }
}
