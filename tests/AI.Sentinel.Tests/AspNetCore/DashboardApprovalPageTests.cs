using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardApprovalPageTests
{
    private const string Secret = "sk-live-0123456789abcdefghijklmn";

    private static ApprovalContext SecretCtx() =>
        new("delete_database", JsonDocument.Parse("{\"path\":\"/etc/x\",\"apiKey\":\"" + Secret + "\"}").RootElement, "<b>why</b>");

    [Fact]
    public async Task Page_SecretInJustification_IsRedacted()
    {
        var store = new InMemoryApprovalStore();
        var ctx = new ApprovalContext("delete_database", default, "apiKey: " + Secret + " please");
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            new DashboardApprovalsTests.TestSec("alice"), DashboardApprovalsTests.MakeSpec(), ctx, TestContext.Current.CancellationToken);
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var html = await (await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId)))
            .Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(Secret, html, StringComparison.Ordinal);
        Assert.Contains("Justification", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_ClearsAStaleErrorOnSuccessAndShowsTheConflictMessage()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var html = await (await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId)))
            .Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("s.textContent = ''; this.parentElement.textContent = 'Approved.'", html, StringComparison.Ordinal);
        Assert.Contains("xhr.status === 409 ? event.detail.xhr.responseText", html, StringComparison.Ordinal);
    }

    private static async Task<(InMemoryApprovalStore Store, ApprovalState.Pending Pending)> PendingAsync()
    {
        var store = new InMemoryApprovalStore();
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(
            new DashboardApprovalsTests.TestSec("alice"), DashboardApprovalsTests.MakeSpec(), SecretCtx(), TestContext.Current.CancellationToken);
        return (store, pending);
    }

    private static Task<HttpResponseMessage> GetAsync(IHost host, string path) =>
        host.GetTestClient().GetAsync(path, TestContext.Current.CancellationToken);

    [Fact]
    public async Task Page_Pending_ShowsFieldsAndRedactedArgs()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var resp = await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId));
        var html = await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.StartsWith("text/html", resp.Content.Headers.ContentType!.ToString(), StringComparison.Ordinal);
        Assert.Contains("delete_database", html, StringComparison.Ordinal);
        Assert.Contains("alice", html, StringComparison.Ordinal);
        Assert.Contains(">p<", html, StringComparison.Ordinal);
        Assert.Contains(pending.RequestedAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture), html, StringComparison.Ordinal);
        Assert.Contains("&lt;b&gt;why&lt;/b&gt;", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<b>why</b>", html, StringComparison.Ordinal);
        Assert.Contains("/etc/x", html, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, html, StringComparison.Ordinal);
        Assert.Contains("btn-approve", html, StringComparison.Ordinal);
        Assert.Contains("btn-deny", html, StringComparison.Ordinal);
        Assert.Contains("name=\"reason\"", html, StringComparison.Ordinal);
        Assert.Contains("hx-post=\"../api/approvals/", html, StringComparison.Ordinal);
        Assert.Contains("href=\"../static/sentinel.css\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_HasNoStoreCacheControl()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var resp = await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId));
        Assert.Contains("no-store", resp.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_UnknownId_SaysNoLongerPending()
    {
        using var host = await DashboardApprovalsTests.BuildHostAsync(new InMemoryApprovalStore(), "ops-bob");
        var resp = await GetAsync(host, "/sentinel/approvals/req-nope");
        var html = await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("no longer pending", html, StringComparison.Ordinal);
        Assert.DoesNotContain("btn-approve", html, StringComparison.Ordinal);
        Assert.Contains("no-store", resp.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_SettledId_SaysNoLongerPending()
    {
        var (store, pending) = await PendingAsync();
        await store.ApproveAsync(pending.RequestId, "ops-bob", null, TestContext.Current.CancellationToken);
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var html = await (await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId)))
            .Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("no longer pending", html, StringComparison.Ordinal);
        Assert.DoesNotContain("btn-approve", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_NoStore_Returns404()
    {
        using var host = await DashboardApprovalsTests.BuildHostAsync(null, "ops-bob");
        var resp = await GetAsync(host, "/sentinel/approvals/req-x");
        var html = await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Contains("No approval store configured", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_NonAdminStore_ShowsExternalMessage()
    {
        using var host = await DashboardApprovalsTests.BuildHostAsync(new DashboardApprovalsTests.ExternalOnlyApprovalStore(), "ops-bob");
        var html = await (await GetAsync(host, "/sentinel/approvals/req-x")).Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("managed externally", html, StringComparison.Ordinal);
        Assert.DoesNotContain("btn-approve", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_ExternalPortalMarker_ShowsExternalMessage()
    {
        using var host = await DashboardApprovalsTests.BuildHostAsync(null, "ops-bob", s => s.AddSingleton<ExternalApprovalPortal>());
        var html = await (await GetAsync(host, "/sentinel/approvals/req-x")).Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("managed externally", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApprovals_ExternalPortalMarker_RendersExternalMessage()
    {
        using var host = await DashboardApprovalsTests.BuildHostAsync(null, "ops-bob", s => s.AddSingleton<ExternalApprovalPortal>());
        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/approvals", TestContext.Current.CancellationToken);
        Assert.Contains("approvals-external", html, StringComparison.Ordinal);
        Assert.Contains("PIM portal", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApprovals_RowLinksToPage()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/approvals", TestContext.Current.CancellationToken);
        Assert.Contains("href=\"approvals/" + Uri.EscapeDataString(pending.RequestId) + "\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_MappedByMapAISentinel()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildMapHostAsync(store, "ops-bob");
        var resp = await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("btn-approve", await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_MappedByUseAISentinel()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store);
        var resp = await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Page_HasFramingProtection()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var resp = await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId));
        Assert.Equal("DENY", Assert.Single(resp.Headers.GetValues("X-Frame-Options")));
        Assert.Equal("frame-ancestors 'none'", Assert.Single(resp.Headers.GetValues("Content-Security-Policy")));
    }

    [Fact]
    public async Task Page_ButtonsAreWiredToEndpointsAndReasonInput()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var html = await (await GetAsync(host, "/sentinel/approvals/" + Uri.EscapeDataString(pending.RequestId)))
            .Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var id = Uri.EscapeDataString(pending.RequestId);
        Assert.Contains("hx-post=\"../api/approvals/" + id + "/deny\" hx-include=\"#deny-reason\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"deny-reason\"", html, StringComparison.Ordinal);
        Assert.Contains("Could not record the decision.", html, StringComparison.Ordinal);
        Assert.Contains("id=\"approval-status\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Deny_WithReasonForm_RecordsReason()
    {
        var (store, pending) = await PendingAsync();
        using var host = await DashboardApprovalsTests.BuildHostAsync(store, "ops-bob");
        var form = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal) { ["reason"] = "too risky" });
        var resp = await host.GetTestClient().PostAsync("/sentinel/api/approvals/" + pending.RequestId + "/deny", form, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var state = await store.EnsureRequestAsync(
            new DashboardApprovalsTests.TestSec("alice"), DashboardApprovalsTests.MakeSpec(), SecretCtx(), TestContext.Current.CancellationToken);
        Assert.Contains("too risky", Assert.IsType<ApprovalState.Denied>(state).Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SpecialCharacterId_OnRealKestrel_PageRendersAndApproveWorks(bool useMap)
    {
        const string id = "a/b?c%d";
        var store = new SettableIdStore(id);
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddRouting();
        AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(builder.Services);
        builder.Services.AddSingleton<IApprovalStore>(store);
        await using var app = builder.Build();
        app.Use(async (ctx, next) =>
        {
            ctx.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, "ops-bob")], "Test"));
            await next(ctx);
        });
        if (useMap)
        {
            app.MapAISentinel("/sentinel");
        }
        else
        {
            app.UseAISentinel("/sentinel");
        }
        await app.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            var baseUrl = app.Urls.First();
            using var client = new HttpClient { BaseAddress = new Uri(baseUrl) };
            var esc = Uri.EscapeDataString(id);
            var page = await client.GetAsync("/sentinel/approvals/" + esc, TestContext.Current.CancellationToken);
            var html = await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Contains("delete_database", html, StringComparison.Ordinal);

            var post = await client.PostAsync("/sentinel/api/approvals/" + esc + "/approve", new StringContent(""), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, post.StatusCode);
            Assert.Equal(id, store.Approved);
        }
        finally
        {
            await app.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task SpecialCharacterId_OnRealKestrel_DenyWorks()
    {
        const string id = "a/b?c%d";
        var store = new SettableIdStore(id);
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddRouting();
        AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(builder.Services);
        builder.Services.AddSingleton<IApprovalStore>(store);
        await using var app = builder.Build();
        app.Use(async (ctx, next) =>
        {
            ctx.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, "ops-bob")], "Test"));
            await next(ctx);
        });
        app.MapAISentinel("/sentinel");
        await app.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            using var client = new HttpClient { BaseAddress = new Uri(app.Urls.First()) };
            var post = await client.PostAsync("/sentinel/api/approvals/" + Uri.EscapeDataString(id) + "/deny", new StringContent(""), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, post.StatusCode);
            Assert.Equal(id, store.Denied);
        }
        finally
        {
            await app.StopAsync(TestContext.Current.CancellationToken);
        }
    }

    private sealed class SettableIdStore(string id) : IApprovalStore, IApprovalAdmin
    {
        public string? Approved { get; private set; }
        public string? Denied { get; private set; }
        public ValueTask<ApprovalState> EnsureRequestAsync(ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct) =>
            throw new NotSupportedException();
        public ValueTask<ApprovalState> WaitForDecisionAsync(string requestId, TimeSpan timeout, CancellationToken ct) =>
            throw new NotSupportedException();
        public ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct)
        {
            Approved = requestId;
            return ValueTask.CompletedTask;
        }
        public ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct)
        {
            Denied = requestId;
            return ValueTask.CompletedTask;
        }
        public async IAsyncEnumerable<PendingRequest> ListPendingAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            await Task.Yield();
            yield return new PendingRequest(id, "alice", "p", "delete_database", default, DateTimeOffset.UtcNow, null);
        }
    }
}
