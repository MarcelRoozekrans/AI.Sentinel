using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardAuthzFeedTests
{
    [Fact]
    public async Task LiveFeed_AuthzDenyEntry_RowHasAuthzClass()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        await store.AppendAsync(NewEntry("AUTHZ-DENY", "denied"), CancellationToken.None);
        await store.AppendAsync(NewEntry("PROMPT-INJECTION", "harmless"), CancellationToken.None);

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed");

        Assert.Contains("audit-row-authz", html, StringComparison.Ordinal);
        Assert.Contains("AUTHZ-DENY", html, StringComparison.Ordinal);
        Assert.Contains("PROMPT-INJECTION", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveFeed_LegacyFilterAuthzParam_StillReturnsOnlyAuthzRows()
    {
        // Backwards-compat: existing ?filter=authz URLs (pre-Phase-2 bookmarks) must
        // still produce AUTHZ-only rows after the FilterAuditEntries migration. The
        // 'authz' alias on IsInCategory is what makes this work; this test pins it.
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        await store.AppendAsync(NewEntry("AUTHZ-DENY", "tenant inactive"), CancellationToken.None);
        await store.AppendAsync(NewEntry("PROMPT-INJECTION", "harmless"), CancellationToken.None);

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed?filter=authz");

        Assert.Contains("audit-row-authz", html, StringComparison.Ordinal);
        Assert.DoesNotContain("PROMPT-INJECTION", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveFeed_FilterAuthz_RestrictsResults()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        await store.AppendAsync(NewEntry("AUTHZ-DENY", "denied"), CancellationToken.None);
        await store.AppendAsync(NewEntry("PROMPT-INJECTION", "harmless"), CancellationToken.None);

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed?filter=authz");

        Assert.Contains("AUTHZ-DENY", html, StringComparison.Ordinal);
        Assert.DoesNotContain("PROMPT-INJECTION", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveFeed_NonAuthzEntry_DoesNotGetAuthzClass()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        await store.AppendAsync(NewEntry("PROMPT-INJECTION", "harmless"), CancellationToken.None);

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed");

        Assert.DoesNotContain("audit-row-authz", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveFeed_EmptyStore_RendersEmptyStateRow()
    {
        var host = await BuildHostAsync();

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed");

        Assert.Contains("feed-empty", html, StringComparison.Ordinal);
        Assert.Contains("agents are quiet", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveFeed_FilterWithNoMatches_RendersFilterEmptyStateRow()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        await store.AppendAsync(NewEntry("PROMPT-INJECTION", "harmless"), CancellationToken.None);

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed?filter=authz");

        Assert.Contains("feed-empty", html, StringComparison.Ordinal);
        Assert.Contains("No events match this filter", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveFeed_AuthzDenyEntry_PolicyCodeRoundTripsToBadgeHtml()
    {
        // End-to-end: AuditEntry → store → /api/feed handler → rendered HTML.
        // Asserts the exact wrapper substring so a future refactor can't silently
        // drop the badge or change its class name without breaking this test.
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        await store.AppendAsync(NewEntry("AUTHZ-DENY", "tenant inactive", policyCode: "tenant_inactive"), CancellationToken.None);

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed");

        Assert.Contains("<span class=\"badge code\">tenant_inactive</span>", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LiveFeed_AuthzDenyEntry_NullPolicyCode_RendersDefaultBadge()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        // PolicyCode left null → renderer must fall back to "policy_denied" so AUTHZ rows
        // always show a badge, even for legacy entries written before Phase 2 plumbing.
        await store.AppendAsync(NewEntry("AUTHZ-DENY", "denied", policyCode: null), CancellationToken.None);

        var client = host.GetTestClient();
        var html = await client.GetStringAsync("/sentinel/api/feed");

        Assert.Contains("<span class=\"badge code\">policy_denied</span>", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DashboardIndex_RendersAuthorizationFilterChip()
    {
        var host = await BuildHostAsync();
        var client = host.GetTestClient();

        var html = await client.GetStringAsync("/sentinel/");

        Assert.Contains("data-filter=\"authorization\"", html, StringComparison.Ordinal);
        Assert.Contains("Authorization", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DashboardIndex_RendersDashboard2_0Elements()
    {
        // Pin the five new-or-renamed elements introduced by Dashboard 2.0 (four chip
        // data-filter values + the search input + the session-pill container) so a silent
        // rename in index.html breaks loudly here instead of in the operator's browser.
        var host = await BuildHostAsync();
        var client = host.GetTestClient();

        var html = await client.GetStringAsync("/sentinel/");

        Assert.Contains("data-filter=\"security\"",      html, StringComparison.Ordinal);
        Assert.Contains("data-filter=\"hallucination\"", html, StringComparison.Ordinal);
        Assert.Contains("data-filter=\"operational\"",   html, StringComparison.Ordinal);
        Assert.Contains("data-filter=\"authorization\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"feed-search\"",            html, StringComparison.Ordinal);
        Assert.Contains("id=\"session-pill-container\"", html, StringComparison.Ordinal);
    }

    private static async Task<IHost> BuildHostAsync()
    {
        return await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                });
                web.Configure(app => app.UseAISentinel("/sentinel"));
            })
            .StartAsync();
    }

    private static AuditEntry NewEntry(string detectorId, string summary, string? policyCode = null) =>
        new(
            Id:           Guid.NewGuid().ToString("N"),
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         "deadbeef00000000",
            PreviousHash: null,
            Severity:     Severity.High,
            DetectorId:   detectorId,
            Summary:      summary,
            PolicyCode:   policyCode);
}
