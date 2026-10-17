using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Approvals;

public class ApprovalAuditingTests
{
    private const string Policy = "p";
    private const string Tool = "delete_database";
    private const string SecretArg = "s3cr3t-arg-value";
    private const string CallerId = "caller-xyz";
    private const string ApproverId = "approver-abc";
    private const string ApproverNote = "note-123";
    private const string DenyReason = "reason-456";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ApprovalSpec MakeSpec(TimeSpan? grant = null) =>
        new() { PolicyName = Policy, GrantDuration = grant ?? TimeSpan.FromMinutes(15) };

    private static ApprovalContext MakeCtx()
    {
        using var doc = JsonDocument.Parse($$"""{"password":"{{SecretArg}}"}""");
        return new ApprovalContext(Tool, doc.RootElement.Clone(), Justification: "because " + SecretArg);
    }

    private static (IApprovalStore Store, RecordingAuditStore Audit) Wrap(IApprovalStore inner, IAuditStore? audit = null)
    {
        var recording = new RecordingAuditStore();
        var services = new ServiceCollection();
        services.AddSingleton(inner);
        services.AddSingleton(audit ?? recording);
        using var sp = services.BuildServiceProvider();
        return (ApprovalStoreAuditing.Resolve(sp)!, recording);
    }

    private static async Task<string> EnsurePendingAsync(IApprovalStore store, TimeSpan? grant = null)
    {
        var state = await store.EnsureRequestAsync(new TestCaller(CallerId), MakeSpec(grant), MakeCtx(), Ct);
        return Assert.IsType<ApprovalState.Pending>(state).RequestId;
    }

    private static void AssertDecision(AuditEntry entry, string policyCode, string outcome, string requestId)
    {
        Assert.Equal(Severity.None, entry.Severity);
        Assert.Equal(AuditEntryKinds.ApprovalDetectorId, entry.DetectorId);
        Assert.Equal(policyCode, entry.PolicyCode);
        Assert.Equal($"{outcome}: policy {Policy}, tool {Tool}, request {requestId}", entry.Summary);
        Assert.True(AuditEntryKinds.IsInformational(entry));
    }

    [Fact]
    public async Task Approve_WritesOneApprovedEntry_WithPolicyToolRequestOnly()
    {
        var (store, audit) = Wrap(new InMemoryApprovalStore());
        var requestId = await EnsurePendingAsync(store);

        await ((IApprovalAdmin)store).ApproveAsync(requestId, ApproverId, ApproverNote, Ct);

        var entry = Assert.Single(audit.Entries);
        AssertDecision(entry, AuditEntryKinds.ApprovedPolicyCode, "Approved", requestId);
        Assert.Null(entry.SessionId);
    }

    [Fact]
    public async Task Deny_WritesOneDeniedEntry()
    {
        var (store, audit) = Wrap(new InMemoryApprovalStore());
        var requestId = await EnsurePendingAsync(store);

        await ((IApprovalAdmin)store).DenyAsync(requestId, ApproverId, DenyReason, Ct);

        var entry = Assert.Single(audit.Entries);
        AssertDecision(entry, AuditEntryKinds.DeniedPolicyCode, "Denied", requestId);
    }

    [Fact]
    public async Task ApproveTwice_SecondWritesNothing()
    {
        var (store, audit) = Wrap(new InMemoryApprovalStore());
        var requestId = await EnsurePendingAsync(store);
        var admin = (IApprovalAdmin)store;

        await admin.ApproveAsync(requestId, ApproverId, null, Ct);
        await admin.ApproveAsync(requestId, ApproverId, null, Ct);
        await admin.DenyAsync(requestId, ApproverId, DenyReason, Ct);

        Assert.Single(audit.Entries);
    }

    [Fact]
    public async Task ExpiredGrantObserved_WritesOneExpiredEntry()
    {
        var time = new ManualTime(DateTimeOffset.Parse("2026-10-17T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var (store, audit) = Wrap(new InMemoryApprovalStore(time));
        var requestId = await EnsurePendingAsync(store, TimeSpan.FromMinutes(1));
        await ((IApprovalAdmin)store).ApproveAsync(requestId, ApproverId, null, Ct);
        time.Now += TimeSpan.FromMinutes(2);

        var expired = await store.EnsureRequestAsync(new TestCaller(CallerId), MakeSpec(TimeSpan.FromMinutes(1)), MakeCtx(), Ct);
        Assert.Equal("expired", Assert.IsType<ApprovalState.Denied>(expired).Reason);
        // The store forgot the expired grant, so the next call opens a fresh request and writes nothing.
        await EnsurePendingAsync(store, TimeSpan.FromMinutes(1));

        var entry = Assert.Single(audit.Entries, e => string.Equals(e.PolicyCode, AuditEntryKinds.ExpiredPolicyCode, StringComparison.Ordinal));
        AssertDecision(entry, AuditEntryKinds.ExpiredPolicyCode, "Expired", requestId);
        Assert.Equal(2, audit.Entries.Count);
    }

    [Fact]
    public async Task WaitTimesOut_WritesTimedOutEntry()
    {
        var (store, audit) = Wrap(new InMemoryApprovalStore());
        var requestId = await EnsurePendingAsync(store);

        var state = await store.WaitForDecisionAsync(requestId, TimeSpan.FromMilliseconds(20), Ct);

        Assert.IsType<ApprovalState.Pending>(state);
        var entry = Assert.Single(audit.Entries);
        AssertDecision(entry, AuditEntryKinds.TimedOutPolicyCode, "Timed out", requestId);
    }

    [Fact]
    public async Task NonAdminStore_ActiveObserved_WritesApprovedOnce()
    {
        var inner = new ExternalStore();
        var audit = new RecordingAuditStore();
        // Two resolutions over the same inner store, as the guard and the chat client each do.
        var (guardView, _) = Wrap(inner, audit);
        var (waitView, _) = Wrap(inner, audit);

        var requestId = await EnsurePendingAsync(guardView);
        inner.Next = new ApprovalState.Active(DateTimeOffset.UtcNow.AddMinutes(5));
        await waitView.WaitForDecisionAsync(requestId, TimeSpan.FromSeconds(1), Ct);
        await waitView.WaitForDecisionAsync(requestId, TimeSpan.FromSeconds(1), Ct);
        await guardView.WaitForDecisionAsync(requestId, TimeSpan.FromSeconds(1), Ct);

        var entry = Assert.Single(audit.Entries);
        AssertDecision(entry, AuditEntryKinds.ApprovedPolicyCode, "Approved", requestId);
    }

    [Fact]
    public async Task NonAdminStore_DeniedObserved_WritesDeniedOnce()
    {
        var inner = new ExternalStore();
        var (store, audit) = Wrap(inner);
        var requestId = await EnsurePendingAsync(store);
        inner.Next = new ApprovalState.Denied("Denied in PIM", DateTimeOffset.UtcNow);

        await store.WaitForDecisionAsync(requestId, TimeSpan.FromSeconds(1), Ct);
        await store.WaitForDecisionAsync(requestId, TimeSpan.FromSeconds(1), Ct);

        var entry = Assert.Single(audit.Entries);
        AssertDecision(entry, AuditEntryKinds.DeniedPolicyCode, "Denied", requestId);
    }

    [Fact]
    public async Task WaitCancelledByCaller_WritesNothing()
    {
        var inner = new ExternalStore();
        var (store, audit) = Wrap(inner);
        var requestId = await EnsurePendingAsync(store);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var state = await store.WaitForDecisionAsync(requestId, TimeSpan.FromSeconds(1), cts.Token);

        Assert.IsType<ApprovalState.Pending>(state);
        Assert.Empty(audit.Entries);
    }

    [Fact]
    public void NoAuditStore_ResolverReturnsInnerUnwrapped()
    {
        var inner = new InMemoryApprovalStore();
        var services = new ServiceCollection();
        services.AddSingleton<IApprovalStore>(inner);
        using var sp = services.BuildServiceProvider();

        Assert.Same(inner, ApprovalStoreAuditing.Resolve(sp));

        using var empty = new ServiceCollection().BuildServiceProvider();
        Assert.Null(ApprovalStoreAuditing.Resolve(empty));
    }

    [Fact]
    public void Wrapper_ImplementsAdminOnlyWhenInnerDoes()
    {
        var (adminStore, _) = Wrap(new InMemoryApprovalStore());
        var (externalStore, _) = Wrap(new ExternalStore());

        Assert.IsAssignableFrom<IApprovalAdmin>(adminStore);
        Assert.IsNotType<InMemoryApprovalStore>(adminStore);
        Assert.False(externalStore is IApprovalAdmin);
        Assert.IsNotType<ExternalStore>(externalStore);
    }

    [Fact]
    public async Task AuditFailure_DoesNotFailTheDecision()
    {
        var inner = new InMemoryApprovalStore();
        var (store, _) = Wrap(inner, new ThrowingAuditStore());
        var requestId = await EnsurePendingAsync(store);

        await ((IApprovalAdmin)store).ApproveAsync(requestId, ApproverId, null, Ct);

        var state = await inner.WaitForDecisionAsync(requestId, TimeSpan.Zero, Ct);
        Assert.IsType<ApprovalState.Active>(state);

        var other = await inner.EnsureRequestAsync(new TestCaller("other"), MakeSpec(), MakeCtx(), Ct);
        var otherId = Assert.IsType<ApprovalState.Pending>(other).RequestId;
        var timedOut = await store.WaitForDecisionAsync(otherId, TimeSpan.FromMilliseconds(10), Ct);
        Assert.IsType<ApprovalState.Pending>(timedOut);
    }

    [Fact]
    public async Task Entries_ContainNoArgumentsNoteOrCallerId()
    {
        var time = new ManualTime(DateTimeOffset.Parse("2026-10-17T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var (store, audit) = Wrap(new InMemoryApprovalStore(time));
        var admin = (IApprovalAdmin)store;

        var approved = await EnsurePendingAsync(store, TimeSpan.FromMinutes(1));
        await admin.ApproveAsync(approved, ApproverId, ApproverNote, Ct);
        time.Now += TimeSpan.FromMinutes(2);
        await store.EnsureRequestAsync(new TestCaller(CallerId), MakeSpec(TimeSpan.FromMinutes(1)), MakeCtx(), Ct);
        var denied = await EnsurePendingAsync(store);
        await admin.DenyAsync(denied, ApproverId, DenyReason, Ct);
        await store.EnsureRequestAsync(new TestCaller(CallerId), MakeSpec(), MakeCtx(), Ct);
        var timedOut = await EnsurePendingAsync(store);
        await store.WaitForDecisionAsync(timedOut, TimeSpan.FromMilliseconds(10), Ct);

        Assert.Equal(
            [AuditEntryKinds.ApprovedPolicyCode, AuditEntryKinds.ExpiredPolicyCode, AuditEntryKinds.DeniedPolicyCode, AuditEntryKinds.TimedOutPolicyCode],
            audit.Entries.Select(e => e.PolicyCode!).ToArray(), StringComparer.Ordinal);
        foreach (var e in audit.Entries)
        {
            foreach (var field in new[] { e.Id, e.DetectorId, e.Summary, e.PolicyCode, e.SessionId, e.Source, e.Hash, e.PreviousHash })
            {
                if (field is null) continue;
                Assert.DoesNotContain(SecretArg, field, StringComparison.Ordinal);
                Assert.DoesNotContain(CallerId, field, StringComparison.Ordinal);
                Assert.DoesNotContain(ApproverId, field, StringComparison.Ordinal);
                Assert.DoesNotContain(ApproverNote, field, StringComparison.Ordinal);
                Assert.DoesNotContain(DenyReason, field, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public async Task Dashboard_ApproveEndpoint_WritesApprovedEntry()
    {
        var inner = new InMemoryApprovalStore();
        var pending = await inner.EnsureRequestAsync(new TestCaller(CallerId), MakeSpec(), MakeCtx(), Ct);
        var requestId = Assert.IsType<ApprovalState.Pending>(pending).RequestId;

        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                    services.AddSingleton<IApprovalStore>(inner);
                });
                web.Configure(app => app.UseAISentinel("/sentinel", branch =>
                    branch.Use(async (ctx, next) =>
                    {
                        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
                            [new Claim(ClaimTypes.Name, ApproverId)], authenticationType: "Test"));
                        await next(ctx);
                    })));
            })
            .StartAsync(Ct);

        var resp = await host.GetTestClient().PostAsync(
            $"/sentinel/api/approvals/{requestId}/approve", new StringContent(""), Ct);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var auditStore = host.Services.GetRequiredService<IAuditStore>();
        var entries = new List<AuditEntry>();
        await foreach (var e in auditStore.QueryAsync(new AuditQuery(), Ct))
        {
            entries.Add(e);
        }
        var entry = Assert.Single(entries, e => string.Equals(e.DetectorId, AuditEntryKinds.ApprovalDetectorId, StringComparison.Ordinal));
        AssertDecision(entry, AuditEntryKinds.ApprovedPolicyCode, "Approved", requestId);
        Assert.False(string.IsNullOrEmpty(entry.Hash));
    }

    private sealed class TestCaller(string id) : ISecurityContext
    {
        public string Id { get; } = id;
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    private sealed class ManualTime(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>A store whose state lives elsewhere, like Entra PIM: no <see cref="IApprovalAdmin"/>.</summary>
    private sealed class ExternalStore : IApprovalStore
    {
        public ApprovalState? Next { get; set; }

        public ValueTask<ApprovalState> EnsureRequestAsync(ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct) =>
            ValueTask.FromResult<ApprovalState>(new ApprovalState.Pending("pim-req-1", "https://pim/req", DateTimeOffset.UtcNow));

        public ValueTask<ApprovalState> WaitForDecisionAsync(string requestId, TimeSpan timeout, CancellationToken ct) =>
            ValueTask.FromResult(ct.IsCancellationRequested || Next is null
                ? new ApprovalState.Pending(requestId, "https://pim/req", DateTimeOffset.UtcNow)
                : Next);
    }

    private sealed class RecordingAuditStore : IAuditStore
    {
        public List<AuditEntry> Entries { get; } = [];

        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct)
        {
            lock (Entries) Entries.Add(entry);
            return ValueTask.FromResult(entry);
        }

        public async IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            await Task.CompletedTask;
            foreach (var e in Entries) yield return e;
        }
    }

    private sealed class ThrowingAuditStore : IAuditStore
    {
        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) =>
            throw new InvalidOperationException("audit store down");

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) =>
            throw new InvalidOperationException("audit store down");
    }
}
