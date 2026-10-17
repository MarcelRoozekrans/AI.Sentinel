using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using System.Text.Json;
using Xunit;
using ZeroAlloc.Authorization;

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
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    [Fact]
    public async Task EnsureRequest_FirstCall_ReturnsPending()
    {
        var store = new InMemoryApprovalStore();
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Pending>(state);
    }

    [Fact]
    public async Task EnsureRequest_RepeatedCall_DedupesByCallerAndPolicy()
    {
        var store = new InMemoryApprovalStore();
        var first = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var second = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Pending>(second);
        Assert.Equal(first.RequestId, ((ApprovalState.Pending)second).RequestId);
    }

    [Fact]
    public async Task ApproveAsync_TransitionsToActive()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        await store.ApproveAsync(pending.RequestId, "approver", note: null, TestContext.Current.CancellationToken);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Active>(state);
    }

    [Fact]
    public async Task DenyAsync_FirstCallObservesDenied_SecondCallCreatesFresh()
    {
        var store = new InMemoryApprovalStore();
        var pending1 = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        await store.DenyAsync(pending1.RequestId, "approver", "no", TestContext.Current.CancellationToken);

        // First call after deny: caller observes the terminal state once.
        var afterDeny = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Denied>(afterDeny);

        // Second call: dedupe was cleared on the previous call → fresh Pending with NEW request id.
        var retry = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var pending2 = Assert.IsType<ApprovalState.Pending>(retry);
        Assert.NotEqual(pending1.RequestId, pending2.RequestId, StringComparer.Ordinal);
    }

    [Fact]
    public async Task ActiveGrant_AfterExpiry_NextCallCreatesFreshRequest()
    {
        var store = new InMemoryApprovalStore();
        var pending1 = (ApprovalState.Pending)await store.EnsureRequestAsync(
            MakeCaller(),
            MakeSpec(grant: TimeSpan.FromMilliseconds(50)),
            MakeCtx(),
            TestContext.Current.CancellationToken);
        await store.ApproveAsync(pending1.RequestId, "approver", null, TestContext.Current.CancellationToken);
        await Task.Delay(150, TestContext.Current.CancellationToken);

        // First call after expiry: observe Denied (terminal state communicated to caller).
        var afterExpiry = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Denied>(afterExpiry);

        // Second call: dedupe was cleared on the previous call → fresh Pending with NEW request id.
        var retry = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var pending2 = Assert.IsType<ApprovalState.Pending>(retry);
        Assert.NotEqual(pending1.RequestId, pending2.RequestId, StringComparer.Ordinal);
    }

    [Fact]
    public async Task EnsureRequest_ConcurrentCreates_ProduceExactlyOneEntry()
    {
        var store = new InMemoryApprovalStore();
        var caller = MakeCaller();
        var tasks = Enumerable.Range(0, 100)
            .Select(_ => Task.Run(() => store.EnsureRequestAsync(caller, MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken).AsTask()))
            .ToArray();
        var results = await Task.WhenAll(tasks);

        // All 100 concurrent calls must observe the same RequestId — dedupe held under contention.
        var pendings = results.OfType<ApprovalState.Pending>().ToArray();
        Assert.Equal(100, pendings.Length);
        Assert.Single(pendings.Select(p => p.RequestId).Distinct(StringComparer.Ordinal));
    }

    [Fact]
    public async Task WaitForDecision_TriggersOnApprove()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var waitTask = store.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken).AsTask();
        await Task.Delay(50, TestContext.Current.CancellationToken);
        await store.ApproveAsync(pending.RequestId, "a", null, TestContext.Current.CancellationToken);
        var result = await waitTask;
        Assert.IsType<ApprovalState.Active>(result);
    }

    [Fact]
    public async Task ListPending_ReturnsOnlyPendingRequests()
    {
        var store = new InMemoryApprovalStore();
        var p1 = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller("a"), MakeSpec("p1"), MakeCtx(), TestContext.Current.CancellationToken);
        await store.EnsureRequestAsync(MakeCaller("b"), MakeSpec("p2"), MakeCtx(), TestContext.Current.CancellationToken);
        await store.ApproveAsync(p1.RequestId, "a", null, TestContext.Current.CancellationToken);

        var pending = new List<PendingRequest>();
        await foreach (var r in store.ListPendingAsync(TestContext.Current.CancellationToken)) pending.Add(r);
        Assert.Single(pending);
        Assert.Equal("p2", pending[0].PolicyName);
    }

    [Fact]
    public async Task DeniedStates_CarryTheRequestId()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTime(DateTimeOffset.Parse("2026-10-17T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var store = new InMemoryApprovalStore(time);

        var denied = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller("a"), MakeSpec(), MakeCtx(), ct);
        await store.DenyAsync(denied.RequestId, "approver", "no", ct);
        var waited = Assert.IsType<ApprovalState.Denied>(await store.WaitForDecisionAsync(denied.RequestId, TimeSpan.Zero, ct));
        Assert.Equal(denied.RequestId, waited.RequestId);
        var observed = Assert.IsType<ApprovalState.Denied>(await store.EnsureRequestAsync(MakeCaller("a"), MakeSpec(), MakeCtx(), ct));
        Assert.Equal(denied.RequestId, observed.RequestId);

        var granted = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller("b"), MakeSpec(grant: TimeSpan.FromMinutes(1)), MakeCtx(), ct);
        await store.ApproveAsync(granted.RequestId, "approver", null, ct);
        time.Now += TimeSpan.FromMinutes(2);
        var expired = Assert.IsType<ApprovalState.Denied>(await store.EnsureRequestAsync(MakeCaller("b"), MakeSpec(grant: TimeSpan.FromMinutes(1)), MakeCtx(), ct));
        Assert.Equal("expired", expired.Reason);
        Assert.Equal(granted.RequestId, expired.RequestId);

        var unknown = Assert.IsType<ApprovalState.Denied>(await store.WaitForDecisionAsync("req-missing", TimeSpan.Zero, ct));
        Assert.Equal("req-missing", unknown.RequestId);
    }

    private sealed class ManualTime(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
