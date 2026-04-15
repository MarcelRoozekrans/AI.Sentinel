using Microsoft.AspNetCore.Builder;

namespace AI.Sentinel.AspNetCore;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseAISentinel(
        this IApplicationBuilder app,
        string pathPrefix = "/ai-sentinel")
    {
        app.Map(pathPrefix, branch =>
        {
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
