using System.Net;
using System.Text.Json;
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

public class DashboardSourceTests
{
    [Fact]
    public async Task Feed_ShowsTheSourceColumn()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("SEC-01", "x", AuditSources.ClaudeCode), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed", TestContext.Current.CancellationToken);

        Assert.Contains("class=\"source-link filter-link\"", html, StringComparison.Ordinal);
        Assert.Contains("data-filter-key=\"source\" data-filter-value=\"claude-code\"", html, StringComparison.Ordinal);
        Assert.Contains(">claude-code</a>", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feed_FilteredBySource()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("SEC-01", "from claude", AuditSources.ClaudeCode), CancellationToken.None);
        await store.AppendAsync(NewEntry("SEC-02", "from proxy", AuditSources.Mcp), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed?source=MCP", TestContext.Current.CancellationToken);

        Assert.Contains("SEC-02", html, StringComparison.Ordinal);
        Assert.DoesNotContain("SEC-01", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feed_SourceFilterWithNoMatch_ShowsFilterEmptyMessageAcrossSevenColumns()
    {
        using var host = await BuildHostAsync();
        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed?source=copilot", TestContext.Current.CancellationToken);

        Assert.Contains("colspan=\"7\"", html, StringComparison.Ordinal);
        Assert.Contains("No events match this filter.", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Export_FilteredBySource()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("SEC-01", "from claude", AuditSources.ClaudeCode), CancellationToken.None);
        await store.AppendAsync(NewEntry("SEC-02", "from proxy", AuditSources.Mcp), CancellationToken.None);

        var resp = await host.GetTestClient().GetAsync("/sentinel/api/export.ndjson?source=mcp", TestContext.Current.CancellationToken);
        var body = await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var lines = body.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var entry = JsonSerializer.Deserialize<AuditEntry>(Assert.Single(lines), AuditJsonContext.Default.AuditEntry);
        Assert.Equal("SEC-02", entry?.DetectorId);
    }

    [Fact]
    public async Task Feed_EntryWithoutSource_RendersEmptyCell()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("SEC-01", "in-process", null), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed", TestContext.Current.CancellationToken);

        Assert.Contains("<td class=\"source\">—</td>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("source-link", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feed_MatchingEntryOlderThanFiftyNewerOnes_StillAppearsWithSourceFilter()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("OLD-MCP", "old proxy entry", AuditSources.Mcp), CancellationToken.None);
        for (var i = 0; i < 60; i++)
            await store.AppendAsync(NewEntry("SEC-NEW", "newer", AuditSources.ClaudeCode), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed?source=mcp", TestContext.Current.CancellationToken);

        Assert.Contains("OLD-MCP", html, StringComparison.Ordinal);
        Assert.DoesNotContain("SEC-NEW", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feed_SourceCombinedWithSession_IntersectsBoth()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("HIT-01", "x", AuditSources.Mcp, "sess-A"), CancellationToken.None);
        await store.AppendAsync(NewEntry("MISS-SESSION", "x", AuditSources.Mcp, "sess-B"), CancellationToken.None);
        await store.AppendAsync(NewEntry("MISS-SOURCE", "x", AuditSources.Copilot, "sess-A"), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed?source=mcp&session=sess-A", TestContext.Current.CancellationToken);

        Assert.Contains("HIT-01", html, StringComparison.Ordinal);
        Assert.DoesNotContain("MISS-", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feed_SourceWithMarkup_IsEncodedInCellTextAndDataAttribute()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("SEC-01", "x", "ev\"il<b>"), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed", TestContext.Current.CancellationToken);

        Assert.DoesNotContain("ev\"il", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<b>", html, StringComparison.Ordinal);
        Assert.Contains("data-filter-value=\"ev&quot;il&lt;b&gt;\"", html, StringComparison.Ordinal);
        Assert.Contains(">ev&quot;il&lt;b&gt;</a>", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feed_WithoutFilters_ShowsNewestEntriesNotOldest()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("SEC-OLDEST", "x", null), CancellationToken.None);
        for (var i = 0; i < 55; i++)
            await store.AppendAsync(NewEntry("SEC-MID", "x", null), CancellationToken.None);
        await store.AppendAsync(NewEntry("SEC-NEWEST", "x", null), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed", TestContext.Current.CancellationToken);

        Assert.Contains("SEC-NEWEST", html, StringComparison.Ordinal);
        Assert.DoesNotContain("SEC-OLDEST", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Feed_SourceCombinedWithCategory_IntersectsBoth()
    {
        using var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(NewEntry("SEC-HIT", "x", AuditSources.Mcp), CancellationToken.None);
        await store.AppendAsync(NewEntry("HAL-MISS-CATEGORY", "x", AuditSources.Mcp), CancellationToken.None);
        await store.AppendAsync(NewEntry("SEC-MISS-SOURCE", "x", AuditSources.Copilot), CancellationToken.None);

        var html = await host.GetTestClient().GetStringAsync("/sentinel/api/feed?source=mcp&filter=security", TestContext.Current.CancellationToken);

        Assert.Contains("SEC-HIT", html, StringComparison.Ordinal);
        Assert.DoesNotContain("MISS", html, StringComparison.Ordinal);
    }

    private static async Task<IHost> BuildHostAsync() =>
        await new HostBuilder()
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

    private static AuditEntry NewEntry(string detectorId, string summary, string? source, string? sessionId = null) =>
        new(
            Id: Guid.NewGuid().ToString("N"),
            Timestamp: DateTimeOffset.UtcNow,
            Hash: "deadbeef00000000",
            PreviousHash: null,
            Severity: Severity.High,
            DetectorId: detectorId,
            Summary: summary,
            SessionId: sessionId,
            Source: source);
}
