using Microsoft.AspNetCore.Builder;

namespace AI.Sentinel.AspNetCore;

public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Mounts the AI.Sentinel dashboard at <paramref name="pathPrefix"/>.
    /// Use <paramref name="configureBranch"/> to add authentication or authorization middleware
    /// before the dashboard endpoints are reached. Example:
    /// <code>
    /// app.UseAISentinel("/ai-sentinel", branch => branch.Use(RequireApiKey));
    /// </code>
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
                endpoints.MapGet("/", DashboardHandlers.IndexAsync);
                endpoints.MapGet("/api/stats", DashboardHandlers.StatsAsync);
                endpoints.MapGet("/api/feed", DashboardHandlers.LiveFeedAsync);
                endpoints.MapGet("/api/trs", DashboardHandlers.TrsStreamAsync);
                endpoints.MapGet("/static/{file}", DashboardHandlers.StaticFileAsync);
            });
        });
        return app;
    }
}
