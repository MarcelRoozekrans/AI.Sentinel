using System.Net;
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

public class DashboardTrendTests
{
    [Fact]
    public async Task Trend_EmptyStore_RendersZeroBuckets()
    {
        var host = await BuildHostAsync();
        var client = host.GetTestClient();

        var resp = await client.GetAsync("/sentinel/api/trend");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("<svg", html, StringComparison.Ordinal);
        // No data points → flat baseline path; should still render the SVG envelope.
    }

    [Fact]
    public async Task Trend_SeededEntry_RendersNonEmptyPath()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        // Recent timestamp so the entry lands inside the 15-minute trend window.
        await store.AppendAsync(NewEntry("SEC-01", "test", Severity.High), CancellationToken.None);

        var client = host.GetTestClient();
        var resp = await client.GetAsync("/sentinel/api/trend");
        var html = await resp.Content.ReadAsStringAsync();

        Assert.Contains("<svg", html, StringComparison.Ordinal);
        Assert.Contains("d=\"M", html, StringComparison.Ordinal);   // SVG path data present
        Assert.Contains("stroke=", html, StringComparison.Ordinal); // stroke colour set per max severity
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

    private static AuditEntry NewEntry(string detectorId, string summary, Severity severity) =>
        new(
            Id:           Guid.NewGuid().ToString("N"),
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         "deadbeef00000000",
            PreviousHash: null,
            Severity:     severity,
            DetectorId:   detectorId,
            Summary:      summary);
}
