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
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardApprovalsTests
{
    [Fact]
    public async Task ListApprovals_NoStoreRegistered_RendersEmpty()
    {
        using var host = await BuildHostAsync(approvalStore: null);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals", TestContext.Current.CancellationToken);
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
        var html = await client.GetStringAsync("/sentinel/api/approvals", TestContext.Current.CancellationToken);
        Assert.Contains("approvals-external", html, StringComparison.Ordinal);
        Assert.Contains("PIM portal", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApprovals_NoPending_RendersEmptyRow()
    {
        var store = new InMemoryApprovalStore();
        using var host = await BuildHostAsync(store);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals", TestContext.Current.CancellationToken);
        Assert.Contains("approvals-empty", html, StringComparison.Ordinal);
        Assert.Contains("No pending approvals", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApprovals_OnePending_RendersTableRow()
    {
        var store = new InMemoryApprovalStore();
        await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);

        using var host = await BuildHostAsync(store);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals", TestContext.Current.CancellationToken);
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
            new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);

        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var client = host.GetTestClient();
        var resp = await client.PostAsync($"/sentinel/api/approvals/{pending.RequestId}/approve", new StringContent(""), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var observed = await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Active>(observed);
    }

    [Fact]
    public async Task Deny_Endpoint_FlipsPendingToDenied()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);

        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var client = host.GetTestClient();
        var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal) { ["reason"] = "no thanks" });
        var resp = await client.PostAsync($"/sentinel/api/approvals/{pending.RequestId}/deny", content, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var observed = await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        var denied = Assert.IsType<ApprovalState.Denied>(observed);
        Assert.Contains("no thanks", denied.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Approve_Endpoint_NoIApprovalAdmin_Returns404()
    {
        var store = new ExternalOnlyApprovalStore();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var client = host.GetTestClient();
        var resp = await client.PostAsync("/sentinel/api/approvals/req-x/approve", new StringContent(""), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task ListApprovals_HostileCallerId_IsHtmlEncoded()
    {
        var store = new InMemoryApprovalStore();
        var caller = new TestSec("<script>alert('xss')</script>");
        await store.EnsureRequestAsync(caller, MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);

        using var host = await BuildHostAsync(store);
        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/approvals", TestContext.Current.CancellationToken);

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
            new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);

        using var host = await BuildHostAsync(store);   // No auth wired in test host
        var client = host.GetTestClient();

        var resp = await client.PostAsync($"/sentinel/api/approvals/{pending.RequestId}/approve", new StringContent(""), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        // State NOT mutated
        var state = await store.EnsureRequestAsync(new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        Assert.IsType<ApprovalState.Pending>(state);
    }

    [Fact]
    public async Task Approve_CrossSiteFetchMetadata_Returns403AndLeavesPending()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", ("Sec-Fetch-Site", "cross-site"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal("Cross-site approval requests are refused.", await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, await PendingCountAsync(store));
    }

    [Fact]
    public async Task Approve_SameSiteFetchMetadata_Returns403()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", ("Sec-Fetch-Site", "same-site"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Deny_MismatchedOrigin_Returns403()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/deny", ("Origin", "https://evil.example"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal(1, await PendingCountAsync(store));
    }

    [Fact]
    public async Task Approve_NullOrigin_Returns403()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", ("Origin", "null"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Theory]
    [InlineData("Sec-Fetch-Site", "same-origin")]
    [InlineData("Sec-Fetch-Site", "none")]
    [InlineData("Origin", "http://localhost")]
    [InlineData("Origin", "http://localhost:80")]
    [InlineData("", "")]
    public async Task Approve_SameOriginOrNoBrowserHeaders_Succeeds(string header, string value)
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var resp = header.Length == 0
            ? await PostAsync(host, $"/sentinel/api/approvals/{id}/approve")
            : await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", (header, value));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(0, await PendingCountAsync(store));
    }

    [Fact]
    public async Task Deny_CrossSiteFetchMetadata_Returns403AndLeavesPending()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/deny", ("Sec-Fetch-Site", "cross-site"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal(1, await PendingCountAsync(store));
    }

    [Theory]
    [InlineData("https://localhost")]
    [InlineData("http://localhost:8080")]
    [InlineData("http://localhost/x")]
    [InlineData("http://localhost/?a=1")]
    public async Task Approve_OriginSchemePortOrPathMismatch_Returns403(string origin)
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store, authenticatedAs: "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", ("Origin", origin));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal(1, await PendingCountAsync(store));
    }

    [Fact]
    public async Task Approve_CrossSite_ViaMapAISentinel_Returns403AndLeavesPending()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildMapHostAsync(store, "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", ("Sec-Fetch-Site", "cross-site"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal(1, await PendingCountAsync(store));
    }

    [Fact]
    public async Task Approve_SameOrigin_ViaMapAISentinel_Succeeds()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildMapHostAsync(store, "ops-bob");
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", ("Sec-Fetch-Site", "same-origin"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(0, await PendingCountAsync(store));
    }

    [Fact]
    public async Task Approve_CrossSite_Anonymous_Returns403NotUnauthorized()
    {
        var (store, id) = await PendingAsync();
        using var host = await BuildHostAsync(store);
        var resp = await PostAsync(host, $"/sentinel/api/approvals/{id}/approve", ("Sec-Fetch-Site", "cross-site"));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    private static async Task<(InMemoryApprovalStore Store, string Id)> PendingAsync()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            new TestSec("alice"), MakeSpec(), MakeCtx(), TestContext.Current.CancellationToken);
        return (store, pending.RequestId);
    }

    private static async Task<int> PendingCountAsync(InMemoryApprovalStore store)
    {
        var count = 0;
        await foreach (var _ in store.ListPendingAsync(TestContext.Current.CancellationToken))
        {
            count++;
        }
        return count;
    }

    private static async Task<HttpResponseMessage> PostAsync(IHost host, string path, params (string Name, string Value)[] headers)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent("") };
        foreach (var (name, value) in headers)
        {
            req.Headers.TryAddWithoutValidation(name, value);
        }
        return await host.GetTestClient().SendAsync(req, TestContext.Current.CancellationToken);
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

    private static async Task<IHost> BuildMapHostAsync(IApprovalStore approvalStore, string authenticatedAs)
    {
        return await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                    services.AddSingleton(approvalStore);
                });
                web.Configure(app =>
                {
                    app.Use(async (ctx, next) =>
                    {
                        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
                            new[] { new Claim(ClaimTypes.Name, authenticatedAs) }, authenticationType: "Test"));
                        await next(ctx);
                    });
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapAISentinel("/sentinel"));
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
