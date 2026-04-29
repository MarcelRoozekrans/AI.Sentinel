using System.Collections.Concurrent;
using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Approvals.EntraPim.Tests;

public class EntraPimApprovalStoreTests
{
    private const string DbAdmin = "Database Administrator";
    private const string DbAdminRoleId = "11111111-1111-1111-1111-111111111111";
    private const string AlicePrincipalId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    private static ApprovalSpec MakeSpec(
        string policy = "AdminApproval",
        string? backend = DbAdmin,
        TimeSpan? grant = null) =>
        new()
        {
            PolicyName = policy,
            BackendBinding = backend,
            GrantDuration = grant ?? TimeSpan.FromMinutes(15),
        };

    private static ApprovalContext MakeCtx(string? justification = null) =>
        new("delete_database", default, justification);

    private static ISecurityContext MakeCaller(string id = AlicePrincipalId) =>
        new TestSecurityContext(id);

    private static EntraPimOptions MakeOptions(TimeSpan? pollInterval = null, TimeSpan? maxBackoff = null)
    {
        var opts = new EntraPimOptions
        {
            TenantId = "00000000-0000-0000-0000-000000000000",
            PollInterval = pollInterval ?? TimeSpan.FromMilliseconds(5),
            PollMaxBackoff = maxBackoff ?? TimeSpan.FromMilliseconds(50),
        };
        return opts;
    }

    private sealed class TestSecurityContext(string id) : ISecurityContext
    {
        public string Id { get; } = id;
#pragma warning disable HLQ001
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
#pragma warning restore HLQ001
    }

    /// <summary>Configurable fake; observable counters; status sequences keyed per request id.</summary>
    private sealed class FakeGraphRoleClient : IGraphRoleClient
    {
        public Dictionary<string, string?> RoleNameToId { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<(string principalId, string roleId), RoleScheduleSnapshot?> ActiveAssignments { get; } = new();
        public HashSet<(string principalId, string roleId)> Eligible { get; } = new();
        public ConcurrentQueue<string> RequestIdSequence { get; } = new();
        public Dictionary<string, Queue<RoleRequestSnapshot>> StatusSequences { get; } = new(StringComparer.Ordinal);
        public ConcurrentBag<(string principalId, string roleId, TimeSpan duration, string justification)> CreateCalls { get; } = new();

        public int ResolveCount;
        public int GetActiveCount;
        public int IsEligibleCount;
        public int GetStatusCount;

        public ValueTask<string?> ResolveRoleIdAsync(string displayName, CancellationToken ct)
        {
            Interlocked.Increment(ref ResolveCount);
            RoleNameToId.TryGetValue(displayName, out var id);
            return new ValueTask<string?>(id);
        }

        public ValueTask<RoleScheduleSnapshot?> GetActiveAssignmentAsync(
            string principalId, string roleId, CancellationToken ct)
        {
            Interlocked.Increment(ref GetActiveCount);
            ActiveAssignments.TryGetValue((principalId, roleId), out var snap);
            return new ValueTask<RoleScheduleSnapshot?>(snap);
        }

        public ValueTask<bool> IsEligibleAsync(string principalId, string roleId, CancellationToken ct)
        {
            Interlocked.Increment(ref IsEligibleCount);
            return new ValueTask<bool>(Eligible.Contains((principalId, roleId)));
        }

        public ValueTask<string> CreateActivationRequestAsync(
            string principalId, string roleId, TimeSpan duration, string justification, CancellationToken ct)
        {
            CreateCalls.Add((principalId, roleId, duration, justification));
            var id = RequestIdSequence.TryDequeue(out var queued) ? queued : $"req-{Guid.NewGuid():N}";
            return new ValueTask<string>(id);
        }

        // When a queue empties, repeat its last value (sticky). Lets a test set up a single
        // status without worrying about the polling cadence draining the queue.
        private readonly Dictionary<string, RoleRequestSnapshot> _stickyLast = new(StringComparer.Ordinal);

        public ValueTask<RoleRequestSnapshot> GetRequestStatusAsync(string requestId, CancellationToken ct)
        {
            Interlocked.Increment(ref GetStatusCount);
            if (StatusSequences.TryGetValue(requestId, out var q) && q.Count > 0)
            {
                var next = q.Dequeue();
                _stickyLast[requestId] = next;
                return new ValueTask<RoleRequestSnapshot>(next);
            }
            if (_stickyLast.TryGetValue(requestId, out var last))
                return new ValueTask<RoleRequestSnapshot>(last);
            return new ValueTask<RoleRequestSnapshot>(new RoleRequestSnapshot("Failed", "no status configured"));
        }
    }

    private static FakeGraphRoleClient MakeFake()
    {
        var fake = new FakeGraphRoleClient();
        fake.RoleNameToId[DbAdmin] = DbAdminRoleId;
        return fake;
    }

    // ---------------------------------------------------------------------
    // 1. EnsureRequest_ActiveSchedule_ReturnsActive
    // ---------------------------------------------------------------------
    [Fact]
    public async Task EnsureRequest_ActiveSchedule_ReturnsActive()
    {
        var fake = MakeFake();
        var expires = DateTimeOffset.UtcNow.AddMinutes(10);
        fake.ActiveAssignments[(AlicePrincipalId, DbAdminRoleId)] =
            new RoleScheduleSnapshot("Provisioned", expires);

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);

        var active = Assert.IsType<ApprovalState.Active>(state);
        Assert.Equal(expires, active.ExpiresAt);
        // Eligibility check should have been skipped — there's already an active schedule.
        Assert.Equal(0, fake.IsEligibleCount);
        Assert.Empty(fake.CreateCalls);
    }

    // ---------------------------------------------------------------------
    // 2. EnsureRequest_NoEligibility_ReturnsDenied
    // ---------------------------------------------------------------------
    [Fact]
    public async Task EnsureRequest_NoEligibility_ReturnsDenied()
    {
        var fake = MakeFake();
        // No active assignment, no eligibility.
        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);

        var denied = Assert.IsType<ApprovalState.Denied>(state);
        Assert.Contains("not eligible", denied.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(fake.CreateCalls);
    }

    // ---------------------------------------------------------------------
    // 3. EnsureRequest_EligibleButNoActive_CreatesRequest_ReturnsPending
    // ---------------------------------------------------------------------
    [Fact]
    public async Task EnsureRequest_EligibleButNoActive_CreatesRequest_ReturnsPending()
    {
        var fake = MakeFake();
        fake.Eligible.Add((AlicePrincipalId, DbAdminRoleId));
        fake.RequestIdSequence.Enqueue("req-pim-001");

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var state = await store.EnsureRequestAsync(
            MakeCaller(), MakeSpec(), MakeCtx(justification: "needed for incident"), default);

        var pending = Assert.IsType<ApprovalState.Pending>(state);
        Assert.Equal("req-pim-001", pending.RequestId);
        Assert.Contains("portal.azure.com", pending.ApprovalUrl, StringComparison.Ordinal);
        Assert.Contains("req-pim-001", pending.ApprovalUrl, StringComparison.Ordinal);

        var createCall = Assert.Single(fake.CreateCalls);
        Assert.Equal(AlicePrincipalId, createCall.principalId);
        Assert.Equal(DbAdminRoleId, createCall.roleId);
        Assert.Equal("needed for incident", createCall.justification);
    }

    // ---------------------------------------------------------------------
    // 4. WaitForDecision_PollsUntilProvisioned
    // ---------------------------------------------------------------------
    [Fact]
    public async Task WaitForDecision_PollsUntilProvisioned()
    {
        var fake = MakeFake();
        const string ReqId = "req-poll-1";
        fake.StatusSequences[ReqId] = new Queue<RoleRequestSnapshot>(new[]
        {
            new RoleRequestSnapshot("PendingApproval", null),
            new RoleRequestSnapshot("PendingApproval", null),
            new RoleRequestSnapshot("Provisioned", null, AlicePrincipalId, DbAdminRoleId),
        });
        // When status flips to Provisioned, the store reads back the schedule for ExpiresAt.
        var expires = DateTimeOffset.UtcNow.AddMinutes(15);
        fake.ActiveAssignments[(AlicePrincipalId, DbAdminRoleId)] =
            new RoleScheduleSnapshot("Provisioned", expires);

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var state = await store.WaitForDecisionAsync(ReqId, TimeSpan.FromSeconds(5), default);

        var active = Assert.IsType<ApprovalState.Active>(state);
        Assert.Equal(expires, active.ExpiresAt);
        Assert.Equal(3, fake.GetStatusCount);
    }

    // ---------------------------------------------------------------------
    // 5. WaitForDecision_HonoursTimeoutOnPending
    // ---------------------------------------------------------------------
    [Fact]
    public async Task WaitForDecision_HonoursTimeoutOnPending()
    {
        var fake = MakeFake();
        const string ReqId = "req-pending-forever";
        // Always pending — make queue effectively infinite.
        var infinite = new Queue<RoleRequestSnapshot>();
        for (var i = 0; i < 10000; i++)
            infinite.Enqueue(new RoleRequestSnapshot("PendingApproval", null));
        fake.StatusSequences[ReqId] = infinite;

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var state = await store.WaitForDecisionAsync(ReqId, TimeSpan.FromMilliseconds(150), default);
        sw.Stop();

        // Final state still pending → the store returns Pending (most recent state) on timeout.
        Assert.IsType<ApprovalState.Pending>(state);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2),
            $"WaitForDecision should respect the timeout; took {sw.Elapsed}.");
    }

    // ---------------------------------------------------------------------
    // 6. RoleResolution_FromDisplayName_CachedAfterFirstHit
    // ---------------------------------------------------------------------
    [Fact]
    public async Task RoleResolution_FromDisplayName_CachedAfterFirstHit()
    {
        var fake = MakeFake();
        fake.Eligible.Add((AlicePrincipalId, DbAdminRoleId));
        fake.RequestIdSequence.Enqueue("req-1");
        fake.RequestIdSequence.Enqueue("req-2");
        fake.RequestIdSequence.Enqueue("req-3");

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        for (var i = 0; i < 3; i++)
            await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);

        Assert.Equal(1, fake.ResolveCount);
    }

    // ---------------------------------------------------------------------
    // 7. PimStatus_PendingApproval_MapsToPending
    // ---------------------------------------------------------------------
    [Fact]
    public async Task PimStatus_PendingApproval_MapsToPending()
    {
        var fake = MakeFake();
        const string ReqId = "req-pa";
        fake.StatusSequences[ReqId] = new Queue<RoleRequestSnapshot>(new[]
        {
            new RoleRequestSnapshot("PendingApproval", null),
        });

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var state = await store.WaitForDecisionAsync(ReqId, TimeSpan.FromMilliseconds(50), default);

        var pending = Assert.IsType<ApprovalState.Pending>(state);
        Assert.Equal(ReqId, pending.RequestId);
        Assert.Contains(ReqId, pending.ApprovalUrl, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------
    // 8. PimStatus_Failed_MapsToDenied
    // ---------------------------------------------------------------------
    [Fact]
    public async Task PimStatus_Failed_MapsToDenied()
    {
        var fake = MakeFake();
        const string ReqId = "req-fail";
        fake.StatusSequences[ReqId] = new Queue<RoleRequestSnapshot>(new[]
        {
            new RoleRequestSnapshot("Failed", "policy violation: scope not permitted"),
        });

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var state = await store.WaitForDecisionAsync(ReqId, TimeSpan.FromSeconds(2), default);

        var denied = Assert.IsType<ApprovalState.Denied>(state);
        Assert.Contains("policy violation", denied.Reason, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------------
    // 9. EnsureRequest_NonGuidCallerId_ReturnsDeniedWithClearMessage
    // ---------------------------------------------------------------------
    // Caller-identity guard: a UPN-shaped or otherwise non-GUID ISecurityContext.Id must
    // be rejected BEFORE any Graph call, with an operator-actionable message — otherwise
    // Graph silently returns empty results and the store reports "caller is not eligible",
    // which is misleading. UPN fallback (§7.4) is a Stage 2 follow-up.
    [Fact]
    public async Task EnsureRequest_NonGuidCallerId_ReturnsDeniedWithClearMessage()
    {
        var fake = MakeFake();
        var store = new EntraPimApprovalStore(fake, MakeOptions());
        var caller = new TestSecurityContext("alice@contoso.com");

        var state = await store.EnsureRequestAsync(caller, MakeSpec(), MakeCtx(), default);

        var denied = Assert.IsType<ApprovalState.Denied>(state);
        Assert.Contains("AAD object ID", denied.Reason, StringComparison.Ordinal);
        Assert.Equal(0, fake.ResolveCount); // No Graph call should have been made
    }

    // ---------------------------------------------------------------------
    // 10. EnsureRequest_SovereignCloud_PortalUrlUsesConfiguredBase
    // ---------------------------------------------------------------------
    // PortalBaseUrl drives the activation-portal link returned in ApprovalState.Pending.
    // Operators on Azure Gov / China / Germany clouds need their cloud's portal, not commercial.
    [Fact]
    public async Task EnsureRequest_SovereignCloud_PortalUrlUsesConfiguredBase()
    {
        var fake = MakeFake();
        fake.Eligible.Add((AlicePrincipalId, DbAdminRoleId));
        fake.RequestIdSequence.Enqueue("req-gov-001");

        var options = MakeOptions();
        options.PortalBaseUrl = "https://portal.azure.us";

        var store = new EntraPimApprovalStore(fake, options);

        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);

        var pending = Assert.IsType<ApprovalState.Pending>(state);
        Assert.StartsWith("https://portal.azure.us/", pending.ApprovalUrl, StringComparison.Ordinal);
        // Commercial cloud URL must NOT be present.
        Assert.DoesNotContain("portal.azure.com", pending.ApprovalUrl, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------
    // 11. EnsureRequest_PortalBaseUrl_TrailingSlashStripped
    // ---------------------------------------------------------------------
    // Defensive: operators may write the base with or without a trailing slash; the URL
    // assembled from the base + "/#view/..." must not produce "//#view/...".
    [Fact]
    public async Task EnsureRequest_PortalBaseUrl_TrailingSlashStripped()
    {
        var fake = MakeFake();
        fake.Eligible.Add((AlicePrincipalId, DbAdminRoleId));
        fake.RequestIdSequence.Enqueue("req-trim-001");

        var options = MakeOptions();
        options.PortalBaseUrl = "https://portal.azure.us/";

        var store = new EntraPimApprovalStore(fake, options);

        var state = await store.EnsureRequestAsync(MakeCaller(), MakeSpec(), MakeCtx(), default);

        var pending = Assert.IsType<ApprovalState.Pending>(state);
        Assert.DoesNotContain("//#view", pending.ApprovalUrl, StringComparison.Ordinal);
        Assert.StartsWith("https://portal.azure.us/#view", pending.ApprovalUrl, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------
    // 12. WaitForDecision_GrantedThenProvisioned_ReturnsActiveAfterProvisioning
    // ---------------------------------------------------------------------
    // PIM corner: "Granted" means the approver granted the request but the schedule
    // hasn't provisioned yet. Maps to Pending — the next poll observes Provisioned and
    // upgrades to Active. Verifies the state machine handles the intermediate phase.
    [Fact]
    public async Task WaitForDecision_GrantedThenProvisioned_ReturnsActiveAfterProvisioning()
    {
        var fake = MakeFake();
        const string ReqId = "req-granted-1";
        fake.StatusSequences[ReqId] = new Queue<RoleRequestSnapshot>(new[]
        {
            new RoleRequestSnapshot("Granted", null),
            new RoleRequestSnapshot("Provisioned", null, AlicePrincipalId, DbAdminRoleId),
        });
        var expires = DateTimeOffset.UtcNow.AddMinutes(15);
        fake.ActiveAssignments[(AlicePrincipalId, DbAdminRoleId)] =
            new RoleScheduleSnapshot("Provisioned", expires);

        var store = new EntraPimApprovalStore(fake, MakeOptions());

        var state = await store.WaitForDecisionAsync(ReqId, TimeSpan.FromSeconds(5), default);

        Assert.IsType<ApprovalState.Active>(state);
        Assert.True(fake.GetStatusCount >= 2,
            "Should poll at least twice — once for Granted, once for Provisioned");
    }
}
