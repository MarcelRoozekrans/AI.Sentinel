using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using AI.Sentinel.AspNetCore;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardMapAISentinelTests
{
    [Fact]
    public async Task MapAISentinel_WithMapFallback_DashboardIndexWinsOverFallback()
    {
        var host = await BuildHostWithFallbackAsync();
        var client = host.GetTestClient();

        var response = await client.GetAsync("/sentinel/");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(200, (int)response.StatusCode);
        Assert.DoesNotContain("FALLBACK", body, StringComparison.Ordinal);
        Assert.Contains("AI.Sentinel", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MapAISentinel_WithMapFallback_StatsApiWinsOverFallback()
    {
        var host = await BuildHostWithFallbackAsync();
        var client = host.GetTestClient();

        var response = await client.GetAsync("/sentinel/api/stats");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(200, (int)response.StatusCode);
        Assert.DoesNotContain("FALLBACK", body, StringComparison.Ordinal);
        Assert.Contains("stat-card", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MapAISentinel_UnknownPathUnderPrefix_FallsThroughToFallback()
    {
        // Paths under the prefix that aren't dashboard routes should fall through to the
        // root fallback (the Map-branch pattern would have 404'd inside the branch instead).
        var host = await BuildHostWithFallbackAsync();
        var client = host.GetTestClient();

        var response = await client.GetAsync("/sentinel/totally-unmapped");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Contains("FALLBACK", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MapAISentinel_NonDashboardPath_StillReachesFallback()
    {
        var host = await BuildHostWithFallbackAsync();
        var client = host.GetTestClient();

        var response = await client.GetAsync("/some-other-spa-route");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Contains("FALLBACK", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MapAISentinel_ReturnsRouteGroupBuilder_ForChainingConventions()
    {
        // Smoke test: the return type must be RouteGroupBuilder so callers can chain
        // .RequireAuthorization, .RequireRateLimiting, .WithMetadata, etc.
        var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        RouteGroupBuilder group = endpoints.MapAISentinel("/sentinel");
                        group.WithMetadata("custom-tag");
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/sentinel/api/stats");

        Assert.Equal(200, (int)response.StatusCode);
    }

    private static async Task<IHost> BuildHostWithFallbackAsync()
    {
        // Reproduces the production scenario: dashboard mapped alongside MapFallback on
        // the same endpoint route table. With MapAISentinel, dashboard routes outrank the
        // catch-all by route specificity. The old UseAISentinel + Map branch pattern lost
        // here because the fallback claimed every path before the branch ran.
        return await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapAISentinel("/sentinel");
                        endpoints.MapFallback(static (HttpContext ctx) =>
                            ctx.Response.WriteAsync("FALLBACK"));
                    });
                });
            })
            .StartAsync();
    }
}
