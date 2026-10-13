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

        Assert.Contains("class=\"source-link\"", html, StringComparison.Ordinal);
        Assert.Contains("data-source=\"claude-code\"", html, StringComparison.Ordinal);
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

    private static AuditEntry NewEntry(string detectorId, string summary, string? source) =>
        new(
            Id:           Guid.NewGuid().ToString("N"),
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         "deadbeef00000000",
            PreviousHash: null,
            Severity:     Severity.High,
            DetectorId:   detectorId,
            Summary:      summary,
            Source:       source);
}
