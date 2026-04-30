using System.Net;
using System.Net.Http;
using System.Security.Claims;
using AI.Sentinel.Approvals;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardApprovalsTests
{
    [Fact]
    public async Task ListApprovals_NoStoreRegistered_RendersEmpty()
    {
        using var host = await BuildHostAsync(approvalStore: null);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals");
        Assert.Contains("approvals-empty", html, StringComparison.Ordinal);
        Assert.Contains("No approval store configured", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApprovals_NoIApprovalAdmin_RendersExternalMessage()
    {
        // Use a store that implements IApprovalStore but NOT IApprovalAdmin (EntraPim shape)
        var store = new ExternalOnlyApprovalStore();
        using var host = await BuildHostAsync(store);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals");
        Assert.Contains("approvals-external", html, StringComparison.Ordinal);
        Assert.Contains("PIM portal", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApprovals_NoPending_RendersEmptyRow()
    {
        var store = new InMemoryApprovalStore();
        using var host = await BuildHostAsync(store);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals");
        Assert.Contains("approvals-empty", html, StringComparison.Ordinal);
        Assert.Contains("No pending approvals", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApprovals_OnePending_RendersTableRow()
    {
        var store = new InMemoryApprovalStore();
        await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), default);

        using var host = await BuildHostAsync(store);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals");
        Assert.Contains("data-request-id=\"req-", html, StringComparison.Ordinal);
        Assert.Contains("alice", html, StringComparison.Ordinal);
        Assert.Contains("delete_database", html, StringComparison.Ordinal);
        Assert.Contains("btn-approve", html, StringComparison.Ordinal);
        Assert.Contains("btn-deny", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Approve_Endpoint_FlipsPendingToActive()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            new TestSec("alice"), MakeSpec(), MakeCtx(), default);

        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var client = host.GetTestClient();
        var resp = await client.PostAsync($"/sentinel/api/approvals/{pending.RequestId}/approve", new StringContent(""));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var observed = await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Active>(observed);
    }

    [Fact]
    public async Task Deny_Endpoint_FlipsPendingToDenied()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            new TestSec("alice"), MakeSpec(), MakeCtx(), default);

        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var client = host.GetTestClient();
        var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal) { ["reason"] = "no thanks" });
        var resp = await client.PostAsync($"/sentinel/api/approvals/{pending.RequestId}/deny", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var observed = await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), default);
        var denied = Assert.IsType<ApprovalState.Denied>(observed);
        Assert.Contains("no thanks", denied.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Approve_Endpoint_NoIApprovalAdmin_Returns404()
    {
        var store = new ExternalOnlyApprovalStore();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var client = host.GetTestClient();
        var resp = await client.PostAsync("/sentinel/api/approvals/req-x/approve", new StringContent(""));
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task ListApprovals_HostileCallerId_IsHtmlEncoded()
    {
        var store = new InMemoryApprovalStore();
        var caller = new TestSec("<script>alert('xss')</script>");
        await store.EnsureRequestAsync(caller, MakeSpec(), MakeCtx(), default);

        using var host = await BuildHostAsync(store);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals");

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;alert", html, StringComparison.Ordinal);
        // After Issue I-1 fix, single quotes also encoded:
        Assert.DoesNotContain("'xss'", html, StringComparison.Ordinal);
        Assert.Contains("&#39;xss&#39;", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Approve_Endpoint_Unauthenticated_Returns401()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            new TestSec("alice"), MakeSpec(), MakeCtx(), default);

        using var host = await BuildHostAsync(store);   // No auth wired in test host
        var client = host.GetTestClient();

        var resp = await client.PostAsync($"/sentinel/api/approvals/{pending.RequestId}/approve", new StringContent(""));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        // State NOT mutated
        var state = await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), default);
        Assert.IsType<ApprovalState.Pending>(state);
    }

    /// <summary>
    /// Builds a test host. When <paramref name="authenticatedAs"/> is non-null, an
    /// auth-injection middleware is wired via the UseAISentinel branch hook so that
    /// HttpContext.User is an authenticated ClaimsPrincipal with that Name. Mirrors
    /// the production posture where operators wrap the dashboard with an auth
    /// middleware via the same branch hook.
    /// </summary>
    private static async Task<IHost> BuildHostAsync(IApprovalStore? approvalStore, string? authenticatedAs = null)
    {
        return await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                    if (approvalStore is not null)
                    {
                        services.AddSingleton<IApprovalStore>(approvalStore);
                    }
                });
                web.Configure(app =>
                {
                    if (authenticatedAs is not null)
                    {
                        app.UseAISentinel("/sentinel", branch =>
                        {
                            branch.Use(async (ctx, next) =>
                            {
                                var identity = new ClaimsIdentity(
                                    new[] { new Claim(ClaimTypes.Name, authenticatedAs) },
                                    authenticationType: "Test");
                                ctx.User = new ClaimsPrincipal(identity);
                                await next(ctx);
                            });
                        });
                    }
                    else
                    {
                        app.UseAISentinel("/sentinel");
                    }
                });
            })
            .StartAsync();
    }

    private static ApprovalSpec MakeSpec() => new() { PolicyName = "p" };
    private static ApprovalContext MakeCtx() => new("delete_database", default, null);

    private sealed record TestSec(string Id) : ISecurityContext
    {
        private static readonly HashSet<string> EmptyRoles = new(StringComparer.Ordinal);
        private static readonly Dictionary<string, string> EmptyClaims = new(StringComparer.Ordinal);
        public IReadOnlySet<string> Roles => EmptyRoles;
        public IReadOnlyDictionary<string, string> Claims => EmptyClaims;
    }

    /// <summary>Approval store that implements IApprovalStore but NOT IApprovalAdmin —
    /// mirrors the EntraPim shape for testing the dashboard's external-store branch.
    /// The dashboard's list endpoint short-circuits before calling these methods, and
    /// the approve endpoint short-circuits with 404, so they should never execute.</summary>
    private sealed class ExternalOnlyApprovalStore : IApprovalStore
    {
        public ValueTask<ApprovalState> EnsureRequestAsync(ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct) =>
            throw new NotSupportedException("ExternalOnlyApprovalStore is a test double for the dashboard's no-admin branch.");
        public ValueTask<ApprovalState> WaitForDecisionAsync(string requestId, TimeSpan timeout, CancellationToken ct) =>
            throw new NotSupportedException("ExternalOnlyApprovalStore is a test double for the dashboard's no-admin branch.");
    }
}
