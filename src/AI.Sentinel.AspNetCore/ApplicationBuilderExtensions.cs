using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AI.Sentinel.AspNetCore;

public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Maps the AI.Sentinel dashboard endpoints under <paramref name="pathPrefix"/> on the
    /// host's endpoint route builder. Returns the <see cref="RouteGroupBuilder"/> so the caller
    /// can apply conventions like <c>.RequireAuthorization(...)</c>, <c>.RequireRateLimiting(...)</c>,
    /// or <c>.WithMetadata(...)</c>.
    /// <para>
    /// Prefer this over <see cref="UseAISentinel"/> in <c>WebApplication</c>-based hosts: it
    /// composes correctly with <c>MapFallbackToFile</c>, Blazor WASM hosting, and authorization
    /// policies because the routes participate in normal endpoint matching.
    /// </para>
    /// </summary>
    public static RouteGroupBuilder MapAISentinel(
        this IEndpointRouteBuilder endpoints,
        string pathPrefix = "/ai-sentinel")
    {
        var group = endpoints.MapGroup(pathPrefix);
        group.MapGet ("/",                              DashboardHandlers.IndexAsync);
        group.MapGet ("/api/stats",                     DashboardHandlers.StatsAsync);
        group.MapGet ("/api/feed",                      DashboardHandlers.LiveFeedAsync);
        group.MapGet ("/api/trs",                       DashboardHandlers.TrsStreamAsync);
        group.MapGet ("/api/approvals",                 DashboardHandlers.ListApprovalsAsync);
        group.MapPost("/api/approvals/{id}/approve",    DashboardHandlers.ApproveAsync);
        group.MapPost("/api/approvals/{id}/deny",       DashboardHandlers.DenyAsync);
        group.MapGet ("/static/{file}",                 DashboardHandlers.StaticFileAsync);
        return group;
    }

    /// <summary>
    /// Mounts the AI.Sentinel dashboard at <paramref name="pathPrefix"/> using a branch pipeline.
    /// Use <paramref name="configureBranch"/> to add authentication or authorization middleware
    /// before the dashboard endpoints are reached. Example:
    /// <code>
    /// app.UseAISentinel("/ai-sentinel", branch => branch.Use(RequireApiKey));
    /// </code>
    /// <para>
    /// In <c>WebApplication</c> hosts that also call <c>MapFallbackToFile</c> (e.g. Blazor WASM),
    /// prefer <see cref="MapAISentinel"/>: a fallback endpoint registered on the root route table
    /// will outrank this branch and swallow every <c>/ai-sentinel/*</c> request.
    /// </para>
    /// </summary>
    public static IApplicationBuilder UseAISentinel(
        this IApplicationBuilder app,
        string pathPrefix = "/ai-sentinel",
        Action<IApplicationBuilder>? configureBranch = null)
    {
        app.Map(pathPrefix, branch =>
        {
            // Caller-supplied middleware runs first (e.g. authentication, IP allowlisting)
            configureBranch?.Invoke(branch);

            branch.UseRouting();
            branch.UseEndpoints(endpoints =>
            {
                endpoints.MapGet ("/",                              DashboardHandlers.IndexAsync);
                endpoints.MapGet ("/api/stats",                     DashboardHandlers.StatsAsync);
                endpoints.MapGet ("/api/feed",                      DashboardHandlers.LiveFeedAsync);
                endpoints.MapGet ("/api/trs",                       DashboardHandlers.TrsStreamAsync);
                endpoints.MapGet ("/api/approvals",                 DashboardHandlers.ListApprovalsAsync);
                endpoints.MapPost("/api/approvals/{id}/approve",    DashboardHandlers.ApproveAsync);
                endpoints.MapPost("/api/approvals/{id}/deny",       DashboardHandlers.DenyAsync);
                endpoints.MapGet ("/static/{file}",                 DashboardHandlers.StaticFileAsync);
            });
        });
        return app;
    }
}
