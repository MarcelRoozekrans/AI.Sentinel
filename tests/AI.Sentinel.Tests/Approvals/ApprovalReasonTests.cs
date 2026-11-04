using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Notifications;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Approvals;

public class ApprovalReasonTests
{
    private const string Reason = "Semantic match 0.91 ≥ 0.80 on $.command: \"delete a namespace\"";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ApprovalSpec MakeSpec() => new() { PolicyName = "semantic:Bash#abc", GrantDuration = TimeSpan.FromMinutes(15) };

    private static ApprovalContext MakeCtx(string? reason) => new("Bash", default, null) { Reason = reason };

    private sealed class Caller(string id) : ISecurityContext
    {
        public string Id { get; } = id;
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    private static async Task<List<PendingRequest>> PendingAsync(InMemoryApprovalStore store)
    {
        var list = new List<PendingRequest>();
        await foreach (var p in ((IApprovalAdmin)store).ListPendingAsync(Ct))
        {
            list.Add(p);
        }
        return list;
    }

    [Fact]
    public async Task InMemory_StoresReason_OnCreate()
    {
        var store = new InMemoryApprovalStore();
        await store.EnsureRequestAsync(new Caller("alice"), MakeSpec(), MakeCtx(Reason), Ct);

        var pending = Assert.Single(await PendingAsync(store));
        Assert.Equal(Reason, pending.Reason);
    }

    [Fact]
    public async Task InMemory_ExistingPending_KeepsFirstReason()
    {
        var store = new InMemoryApprovalStore();
        await store.EnsureRequestAsync(new Caller("alice"), MakeSpec(), MakeCtx(Reason), Ct);
        await store.EnsureRequestAsync(new Caller("alice"), MakeSpec(), MakeCtx("a later reason"), Ct);

        var pending = Assert.Single(await PendingAsync(store));
        Assert.Equal(Reason, pending.Reason);
    }

    [Fact]
    public async Task InMemory_RuleBasedRequest_HasNullReason()
    {
        var store = new InMemoryApprovalStore();
        await store.EnsureRequestAsync(new Caller("alice"), MakeSpec(), MakeCtx(null), Ct);

        Assert.Null(Assert.Single(await PendingAsync(store)).Reason);
    }

    private static AuthorizationDecision.RequireApprovalDecision Decision(string? reason) =>
        AuthorizationDecision.RequireApproval(
            "semantic:Bash#abc", "req-1", "sentinel://approve/req-1", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1))
        with
        { Reason = reason };

    [Fact]
    public void Receipt_IncludesReasonLine_WhenSet()
    {
        var text = ApprovalReceipt.Format("Bash", Decision(Reason));
        Assert.Contains($"Rule: semantic:Bash#abc\nReason: {Reason}\n", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Receipt_NoReasonLine_WhenNull()
    {
        var text = ApprovalReceipt.Format("Bash", Decision(null));
        Assert.DoesNotContain("Reason:", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Notification_SerialisesReason_AndOmitsWhenNull()
    {
        var pending = new ApprovalState.Pending("req-1", "sentinel://approve/req-1", DateTimeOffset.UtcNow);
        var settings = new ApprovalNotifierSettings(new Uri("https://example.com/hook"), new Dictionary<string, string>(StringComparer.Ordinal), false, null, false);

        var with = ApprovalNotification.Create(pending, "alice", "semantic:Bash#abc", MakeCtx(Reason), settings);
        var json = JsonSerializer.Serialize(with, ApprovalNotificationJsonContext.Default.ApprovalNotification);
        using (var doc = JsonDocument.Parse(json))
        {
            Assert.Equal(Reason, doc.RootElement.GetProperty("reason").GetString());
        }

        var without = ApprovalNotification.Create(pending, "alice", "p", MakeCtx(null), settings);
        var plain = JsonSerializer.Serialize(without, ApprovalNotificationJsonContext.Default.ApprovalNotification);
        using var plainDoc = JsonDocument.Parse(plain);
        Assert.False(plainDoc.RootElement.TryGetProperty("reason", out _));
    }

    [Fact]
    public async Task Audit_RequestEntry_ContainsReason()
    {
        using var audit = new RingBufferAuditStore();
        var services = new ServiceCollection();
        services.AddSingleton<IApprovalStore>(new InMemoryApprovalStore());
        services.AddSingleton<IAuditStore>(audit);
        using var sp = services.BuildServiceProvider();
        var store = ApprovalStoreAuditing.Resolve(sp)!;

        var state = (ApprovalState.Pending)await store.EnsureRequestAsync(new Caller("alice"), MakeSpec(), MakeCtx(Reason), Ct);
        // A reuse of the open request is not a new request.
        await store.EnsureRequestAsync(new Caller("alice"), MakeSpec(), MakeCtx(Reason), Ct);

        var entries = new List<AuditEntry>();
        await foreach (var e in audit.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, Ct))
        {
            entries.Add(e);
        }
        var entry = Assert.Single(entries);
        Assert.Equal(AuditEntryKinds.RequestedPolicyCode, entry.PolicyCode);
        Assert.Contains(Reason, entry.Summary, StringComparison.Ordinal);
        Assert.Equal(state.RequestId, ApprovalStoreAuditing.RequestIdOf(entry.Summary));
        Assert.True(AuditEntryKinds.IsInformational(entry));
        Assert.False(AuditEntryKinds.IsApproval(entry));
    }

    private static DefaultToolCallGuard BuildGuard() =>
        new(
            bindings: [],
            policiesByName: new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal),
            @default: ToolPolicyDefault.Allow,
            approvalStore: null,
            logger: Microsoft.Extensions.Logging.Abstractions.NullLogger<DefaultToolCallGuard>.Instance);

    private sealed class CapturingStore : IApprovalStore
    {
        public ApprovalContext? Last { get; private set; }

        public ValueTask<ApprovalState> EnsureRequestAsync(ISecurityContext c, ApprovalSpec s, ApprovalContext ctx, CancellationToken t)
        {
            Last = ctx;
            return ValueTask.FromResult<ApprovalState>(new ApprovalState.Pending("req-1", "sentinel://approve/req-1", DateTimeOffset.UtcNow));
        }

        public ValueTask<ApprovalState> WaitForDecisionAsync(string id, TimeSpan to, CancellationToken t) =>
            throw new NotSupportedException();
    }

    [Fact]
    public async Task Guard_PassesReason_IntoContextAndDecision()
    {
        var store = new CapturingStore();
        var d = await BuildGuard().EvaluateApprovalAsync(new Caller("alice"), "Bash", default, MakeSpec(), store, Ct, Reason);

        Assert.Equal(Reason, store.Last!.Reason);
        Assert.Equal(Reason, Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d).Reason);
    }

    [Fact]
    public async Task Guard_ReusedPending_ShowsTheFirstReason()
    {
        var store = new InMemoryApprovalStore();
        var guard = BuildGuard();
        var first = await guard.EvaluateApprovalAsync(new Caller("alice"), "Bash", default, MakeSpec(), store, Ct, Reason);
        var second = await guard.EvaluateApprovalAsync(
            new Caller("alice"), "Bash", default, MakeSpec(), store, Ct, "Semantic check failed: timeout; approval required (fail closed)");

        Assert.Equal(Reason, Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(first).Reason);
        Assert.Equal(Reason, Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(second).Reason);
    }

    [Fact]
    public async Task Audit_RuleBasedRequest_WritesNoRequestEntry()
    {
        using var audit = new RingBufferAuditStore();
        var services = new ServiceCollection();
        services.AddSingleton<IApprovalStore>(new InMemoryApprovalStore());
        services.AddSingleton<IAuditStore>(audit);
        using var sp = services.BuildServiceProvider();
        var store = ApprovalStoreAuditing.Resolve(sp)!;

        await store.EnsureRequestAsync(new Caller("alice"), MakeSpec(), MakeCtx(null), Ct);

        await foreach (var _ in audit.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, Ct))
        {
            Assert.Fail("No entry expected.");
        }
    }
}
