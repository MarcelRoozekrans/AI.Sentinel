using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;
using AI.Sentinel.AspNetCore;

namespace AI.Sentinel.Tests.AspNetCore;

/// <summary>
/// The dashboard page loads its panels and stylesheet through relative URLs, so it only works
/// at the prefix with a trailing slash. The bare prefix redirects there.
/// </summary>
public class DashboardTrailingSlashTests
{
    [Fact]
    public async Task MapAISentinel_BarePrefix_RedirectsToTrailingSlash()
    {
        using var host = await StartAsync(MapAISentinel);

        using var response = await SendAsync(host, "/sentinel");

        Assert.Equal(302, (int)response.StatusCode);
        Assert.Equal("/sentinel/", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task MapAISentinel_BarePrefixWithQuery_KeepsQuery()
    {
        using var host = await StartAsync(MapAISentinel);

        using var response = await SendAsync(host, "/sentinel?id=1");

        Assert.Equal(302, (int)response.StatusCode);
        Assert.Equal("/sentinel/?id=1", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task MapAISentinel_WithPathBase_KeepsPathBase()
    {
        using var host = await StartAsync(app =>
        {
            app.UsePathBase("/app");
            MapAISentinel(app);
        });

        using var response = await SendAsync(host, "/app/sentinel");

        Assert.Equal(302, (int)response.StatusCode);
        Assert.Equal("/app/sentinel/", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task MapAISentinel_RootMountUnderPathBase_RedirectsToPathBaseSlash()
    {
        // Under a path base a root mount sees an empty path, not "/".
        using var host = await StartAsync(app =>
        {
            app.UsePathBase("/app");
            app.UseRouting();
            app.UseEndpoints(endpoints => endpoints.MapAISentinel(""));
        });

        using var response = await SendAsync(host, "/app");

        Assert.Equal(302, (int)response.StatusCode);
        Assert.Equal("/app/", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task MapAISentinel_RequireAuthorization_BarePrefix_Returns401()
    {
        using var host = await StartAsync(
            app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(endpoints => endpoints.MapAISentinel("/sentinel").RequireAuthorization());
            },
            services =>
            {
                services.AddAuthentication(AnonymousHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, AnonymousHandler>(AnonymousHandler.SchemeName, _ => { });
                services.AddAuthorization();
            });

        using var response = await SendAsync(host, "/sentinel");

        Assert.Equal(401, (int)response.StatusCode);
    }

    [Fact]
    public async Task MapAISentinel_TrailingSlash_ServesPage()
    {
        using var host = await StartAsync(MapAISentinel);

        using var response = await SendAsync(host, "/sentinel/");
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Contains("hx-get=\"api/stats\"", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UseAISentinel_BarePrefix_RedirectsToTrailingSlash()
    {
        using var host = await StartAsync(app => app.UseAISentinel("/sentinel"));

        using var response = await SendAsync(host, "/sentinel");

        Assert.Equal(302, (int)response.StatusCode);
        Assert.Equal("/sentinel/", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task UseAISentinel_WithPathBaseAndQuery_KeepsBoth()
    {
        using var host = await StartAsync(app =>
        {
            app.UsePathBase("/app");
            app.UseAISentinel("/sentinel");
        });

        using var response = await SendAsync(host, "/app/sentinel?id=1");

        Assert.Equal(302, (int)response.StatusCode);
        Assert.Equal("/app/sentinel/?id=1", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task UseAISentinel_TrailingSlash_ServesPage()
    {
        using var host = await StartAsync(app => app.UseAISentinel("/sentinel"));

        using var response = await SendAsync(host, "/sentinel/");
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Contains("hx-get=\"api/stats\"", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UseAISentinel_BlockingBranch_BarePrefix_Returns403()
    {
        using var host = await StartAsync(app => app.UseAISentinel("/sentinel", branch =>
            branch.Use((HttpContext ctx, RequestDelegate _) =>
            {
                ctx.Response.StatusCode = 403;
                return Task.CompletedTask;
            })));

        using var response = await SendAsync(host, "/sentinel");

        Assert.Equal(403, (int)response.StatusCode);
    }

    private static void MapAISentinel(IApplicationBuilder app)
    {
        app.UseRouting();
        app.UseEndpoints(endpoints => endpoints.MapAISentinel("/sentinel"));
    }

    private static async Task<IHost> StartAsync(
        Action<IApplicationBuilder> configure,
        Action<IServiceCollection>? configureServices = null) =>
        await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                    configureServices?.Invoke(services);
                });
                web.Configure(configure);
            })
            .StartAsync(TestContext.Current.CancellationToken);

    // TestServer's own client does not follow redirects, so the 302 itself is visible.
    private static Task<HttpResponseMessage> SendAsync(IHost host, string path) =>
        host.GetTestClient().GetAsync(path, TestContext.Current.CancellationToken);

    // Authenticates nobody, so RequireAuthorization challenges every request with a 401.
    private sealed class AnonymousHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "Anonymous";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());
    }
}
