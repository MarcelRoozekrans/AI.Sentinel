using System.Globalization;
using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Approvals.Sqlite.Tests;

public sealed class SqliteApprovalStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"approvals-{Guid.NewGuid():N}.db"));

    public void Dispose()
    {
        TryDelete(_dbPath);
        TryDelete(_dbPath + "-wal");
        TryDelete(_dbPath + "-shm");
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static ApprovalSpec MakeSpec(string policy = "p", TimeSpan? grant = null) =>
        new() { PolicyName = policy, GrantDuration = grant ?? TimeSpan.FromMinutes(15) };

    private static ApprovalContext MakeCtx() => new("delete_database", default, null);

    private static ISecurityContext MakeCaller(string id = "alice") =>
        new TestSecurityContext(id);

    private sealed class TestSecurityContext(string id) : ISecurityContext
    {
        public string Id { get; } = id;
#pragma warning disable HLQ001 // Boxing on init is fine for a test helper
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
#pragma warning restore HLQ001
    }

    private SqliteApprovalStore NewStore() =>
        new(new SqliteApprovalStoreOptions
        {
            DatabasePath = _dbPath,
            PollInterval = TimeSpan.FromMilliseconds(25),
        });

    [Fact]
    public async Task EnsureRequest_FirstCall_ReturnsPending()
    {
        await using var store = NewStore();
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Pending>(state);
    }

    [Fact]
    public async Task EnsureRequest_RepeatedCall_DedupesByCallerAndPolicy()
    {
        await using var store = NewStore();
        var first = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var second = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var pending2 = Assert.IsType<ApprovalState.Pending>(second);
        Assert.Equal(first.RequestId, pending2.RequestId);
    }

    [Fact]
    public async Task ApproveAsync_TransitionsToActive()
    {
        await using var store = NewStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        await store.ApproveAsync(pending.RequestId, "approver", note: null, default);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Active>(state);
    }

    [Fact]
    public async Task DenyAsync_FirstCallObservesDenied_SecondCallCreatesFresh()
    {
        await using var store = NewStore();
        var pending1 = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        await store.DenyAsync(pending1.RequestId, "approver", "no", default);

        // First call after deny: caller observes the terminal state once.
        var afterDeny = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Denied>(afterDeny);

        // Second call: dedupe was cleared on the previous call → fresh Pending with NEW request id.
        var retry = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var pending2 = Assert.IsType<ApprovalState.Pending>(retry);
        Assert.NotEqual(pending1.RequestId, pending2.RequestId);
    }

    [Fact]
    public async Task ActiveGrant_AfterExpiry_NextCallCreatesFreshRequest()
    {
        await using var store = NewStore();
        var pending1 = (ApprovalState.Pending)await store.EnsureRequestAsync(
            MakeCaller(),
            MakeSpec(grant: TimeSpan.FromMilliseconds(50)),
            MakeCtx(),
            default);
        await store.ApproveAsync(pending1.RequestId, "approver", null, default);
        await Task.Delay(150);

        // First call after expiry: observe Denied (terminal state communicated to caller).
        var afterExpiry = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Denied>(afterExpiry);

        // Second call: dedupe was cleared on the previous call → fresh Pending with NEW request id.
        var retry = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var pending2 = Assert.IsType<ApprovalState.Pending>(retry);
        Assert.NotEqual(pending1.RequestId, pending2.RequestId);
    }

    [Fact]
    public async Task WaitForDecision_TriggersOnApprove()
    {
        await using var store = NewStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var waitTask = store.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(5), default).AsTask();
        await Task.Delay(50);
        await store.ApproveAsync(pending.RequestId, "a", null, default);
        var result = await waitTask;
        Assert.IsType<ApprovalState.Active>(result);
    }

    [Fact]
    public async Task WaitForDecision_ExternalCancellation_Throws()
    {
        await using var store = NewStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);

        using var cts = new CancellationTokenSource();
        var waitTask = store.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(30), cts.Token).AsTask();
        await Task.Delay(50);
        cts.Cancel();

        await Assert.ThrowsAsync<TaskCanceledException>(() => waitTask);
    }

    [Fact]
    public async Task ListPending_ReturnsOnlyPendingRequests()
    {
        await using var store = NewStore();
        var p1 = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller("a"), MakeSpec("p1"), MakeCtx(), default);
        await store.EnsureRequestAsync(MakeCaller("b"), MakeSpec("p2"), MakeCtx(), default);
        await store.ApproveAsync(p1.RequestId, "a", null, default);

        var pending = new List<PendingRequest>();
        await foreach (var r in store.ListPendingAsync(default)) pending.Add(r);
        Assert.Single(pending);
        Assert.Equal("p2", pending[0].PolicyName);
    }

    [Fact]
    public async Task DenyAsync_StatePersistsAcrossReopen()
    {
        string requestId;
        await using (var store1 = new SqliteApprovalStore(new SqliteApprovalStoreOptions { DatabasePath = _dbPath }))
        {
            var pending = (ApprovalState.Pending)await store1.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
            await store1.DenyAsync(pending.RequestId, "approver", "no", default);
            requestId = pending.RequestId;
        }

        // Reopen and verify the deny survived
        await using var store2 = new SqliteApprovalStore(new SqliteApprovalStoreOptions { DatabasePath = _dbPath });
        var observed = await store2.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);
        var denied = Assert.IsType<ApprovalState.Denied>(observed);
        Assert.Equal("no", denied.Reason);
    }
}
