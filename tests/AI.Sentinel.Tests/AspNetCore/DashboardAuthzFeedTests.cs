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
    public async Task DashboardIndex_RendersAuthorizationFilterChip()
    {
        var host = await BuildHostAsync();
        var client = host.GetTestClient();

        var html = await client.GetStringAsync("/sentinel/");

        Assert.Contains("data-filter=\"authz\"", html, StringComparison.Ordinal);
        Assert.Contains("Authorization", html, StringComparison.Ordinal);
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

    private static AuditEntry NewEntry(string detectorId, string summary) =>
        new(
            Id:           Guid.NewGuid().ToString("N"),
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         "deadbeef00000000",
            PreviousHash: null,
            Severity:     Severity.High,
            DetectorId:   detectorId,
            Summary:      summary);
}
