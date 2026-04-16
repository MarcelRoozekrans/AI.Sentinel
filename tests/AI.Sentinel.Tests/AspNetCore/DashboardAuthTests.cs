using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using AI.Sentinel.AspNetCore;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardAuthTests
{
    [Fact]
    public async Task UseAISentinel_WithAuthMiddleware_IsCalledBeforeEndpoints()
    {
        bool authMiddlewareCalled = false;

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
                    app.UseAISentinel("/sentinel", branch =>
                    {
                        branch.Use(async (ctx, next) =>
                        {
                            authMiddlewareCalled = true;
                            await next(ctx);
                        });
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/sentinel/");

        Assert.True(authMiddlewareCalled, "Auth middleware should have been called");
    }

    [Fact]
    public async Task UseAISentinel_WithBlockingMiddleware_Returns403()
    {
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
                    app.UseAISentinel("/sentinel", branch =>
                    {
                        branch.Use((RequestDelegate _) => async ctx =>
                        {
                            ctx.Response.StatusCode = 403;
                            await ctx.Response.CompleteAsync();
                        });
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/sentinel/");

        Assert.Equal(403, (int)response.StatusCode);
    }

    [Fact]
    public async Task StaticFileAsync_UnlistedFile_Returns404()
    {
        var host = await new HostBuilder()
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

        var client = host.GetTestClient();
        var response = await client.GetAsync("/sentinel/static/evil.txt");

        Assert.Equal(404, (int)response.StatusCode);
    }
}
