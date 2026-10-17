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
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
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
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Pending>(state);
    }

    [Fact]
    public async Task EnsureRequest_RepeatedCall_DedupesByCallerAndPolicy()
    {
        await using var store = NewStore();
        var first = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var second = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var pending2 = Assert.IsType<ApprovalState.Pending>(second);
        Assert.Equal(first.RequestId, pending2.RequestId);
    }

    [Fact]
    public async Task ApproveAsync_TransitionsToActive()
    {
        await using var store = NewStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        await store.ApproveAsync(pending.RequestId, "approver", note: null, TestContext.Current.CancellationToken);
        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Active>(state);
    }

    [Fact]
    public async Task DenyAsync_FirstCallObservesDenied_SecondCallCreatesFresh()
    {
        await using var store = NewStore();
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
        await using var store = NewStore();
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
    public async Task WaitForDecision_TriggersOnApprove()
    {
        await using var store = NewStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var waitTask = store.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken).AsTask();
        await Task.Delay(50, TestContext.Current.CancellationToken);
        await store.ApproveAsync(pending.RequestId, "a", null, TestContext.Current.CancellationToken);
        var result = await waitTask;
        Assert.IsType<ApprovalState.Active>(result);
    }

    [Fact]
    public async Task WaitForDecision_ExternalCancellation_Throws()
    {
        await using var store = NewStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);

        using var cts = new CancellationTokenSource();
        var waitTask = store.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(30), cts.Token).AsTask();
        await Task.Delay(50, TestContext.Current.CancellationToken);
        cts.Cancel();

        // ThrowsAsync demands an exact type, but which cancellation exception surfaces is a race:
        // a token tripped inside Task.Delay yields TaskCanceledException, one observed by an earlier
        // await in the poll loop yields OperationCanceledException. The contract is "cancellation
        // propagates", so assert that rather than an implementation detail.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waitTask);
    }

    [Fact]
    public async Task ListPending_ReturnsOnlyPendingRequests()
    {
        await using var store = NewStore();
        var p1 = (ApprovalState.Pending)await store.EnsureRequestAsync(MakeCaller("a"), MakeSpec("p1"), MakeCtx(), TestContext.Current.CancellationToken);
        await store.EnsureRequestAsync(MakeCaller("b"), MakeSpec("p2"), MakeCtx(), TestContext.Current.CancellationToken);
        await store.ApproveAsync(p1.RequestId, "a", null, TestContext.Current.CancellationToken);

        var pending = new List<PendingRequest>();
        await foreach (var r in store.ListPendingAsync(TestContext.Current.CancellationToken)) pending.Add(r);
        Assert.Single(pending);
        Assert.Equal("p2", pending[0].PolicyName);
    }

    [Fact]
    public async Task DenyAsync_StatePersistsAcrossReopen()
    {
        string requestId;
        await using (var store1 = new SqliteApprovalStore(new SqliteApprovalStoreOptions { DatabasePath = _dbPath }))
        {
            var pending = (ApprovalState.Pending)await store1.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
            await store1.DenyAsync(pending.RequestId, "approver", "no", TestContext.Current.CancellationToken);
            requestId = pending.RequestId;
        }

        // Reopen and verify the deny survived
        await using var store2 = new SqliteApprovalStore(new SqliteApprovalStoreOptions { DatabasePath = _dbPath });
        var observed = await store2.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var denied = Assert.IsType<ApprovalState.Denied>(observed);
        Assert.Equal("no", denied.Reason);
    }

    [Fact]
    public async Task DeniedStates_CarryTheRequestId()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTime(DateTimeOffset.Parse("2026-10-17T10:00:00Z", CultureInfo.InvariantCulture));
        await using var store = new SqliteApprovalStore(new SqliteApprovalStoreOptions { DatabasePath = _dbPath }, time);

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

    [Fact]
    public async Task StoresOnOneFile_RacingEnsureRequest_CreateOneRequest()
    {
        // Each store has its own connection and lock, standing in for one hook process. Only the
        // database can stop them from inserting a request each for the same caller and policy.
        var stores = Enumerable.Range(0, 8).Select(_ => NewStore()).ToArray();
        try
        {
            for (var round = 0; round < 20; round++)
            {
                var policy = string.Create(CultureInfo.InvariantCulture, $"p{round}");
                var states = await EnsureFromAllAtOnceAsync(stores, policy);

                Assert.Single(PendingRequestIds(states));
                Assert.Equal(1L, await CountRowsAsync(policy));
            }
        }
        finally
        {
            foreach (var store in stores)
            {
                await store.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task StoresOnOneFile_RacingApproveAndDeny_AllObserveTheOneDecision()
    {
        await using var first = NewStore();
        await using var second = NewStore();

        for (var round = 0; round < 20; round++)
        {
            var policy = string.Create(CultureInfo.InvariantCulture, $"p{round}");
            var pending = (ApprovalState.Pending)await first.EnsureRequestAsync(MakeCaller(), MakeSpec(policy), MakeCtx(), TestContext.Current.CancellationToken);

            using var start = new Barrier(2);
            await Task.WhenAll(
                Task.Run(
                    () =>
                    {
                        start.SignalAndWait(TestContext.Current.CancellationToken);
                        return first.ApproveAsync(pending.RequestId, "approver", note: null, CancellationToken.None).AsTask();
                    },
                    TestContext.Current.CancellationToken),
                Task.Run(
                    () =>
                    {
                        start.SignalAndWait(TestContext.Current.CancellationToken);
                        return second.DenyAsync(pending.RequestId, "approver", "no", CancellationToken.None).AsTask();
                    },
                    TestContext.Current.CancellationToken));

            // The first decision wins; the other finds the request no longer pending. Both
            // stores must then report that one decision, not a fresh request.
            var seenByFirst = await first.WaitForDecisionAsync(pending.RequestId, TimeSpan.Zero, TestContext.Current.CancellationToken);
            var seenBySecond = await second.WaitForDecisionAsync(pending.RequestId, TimeSpan.Zero, TestContext.Current.CancellationToken);
            Assert.True(seenByFirst is ApprovalState.Active or ApprovalState.Denied, $"unexpected {seenByFirst}");
            Assert.Equal(seenByFirst.GetType(), seenBySecond.GetType());

            var observed = await second.EnsureRequestAsync(MakeCaller(), MakeSpec(policy), MakeCtx(), TestContext.Current.CancellationToken);
            Assert.Equal(seenByFirst.GetType(), observed.GetType());

            // Observing a denial deletes the request so the next call starts fresh; a grant stays.
            Assert.Equal(observed is ApprovalState.Active ? 1L : 0L, await CountRowsAsync(policy));
        }
    }

    private static async Task<ApprovalState[]> EnsureFromAllAtOnceAsync(SqliteApprovalStore[] stores, string policy)
    {
        using var start = new Barrier(stores.Length);
        return await Task.WhenAll(stores.Select(store => Task.Run(
            () =>
            {
                start.SignalAndWait(TestContext.Current.CancellationToken);
                return store.EnsureRequestAsync(MakeCaller(), MakeSpec(policy), MakeCtx(), CancellationToken.None).AsTask();
            },
            TestContext.Current.CancellationToken)));
    }

    private static HashSet<string> PendingRequestIds(ApprovalState[] states) =>
        states.Select(s => Assert.IsType<ApprovalState.Pending>(s).RequestId).ToHashSet(StringComparer.Ordinal);

    private async Task<long> CountRowsAsync(string policy)
    {
        await using var raw = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath};Pooling=False");
        await raw.OpenAsync(TestContext.Current.CancellationToken);
        using var cmd = raw.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM approval_requests WHERE policy_name = $policy;";
        cmd.Parameters.AddWithValue("$policy", policy);
        return (long)(await cmd.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }
}
