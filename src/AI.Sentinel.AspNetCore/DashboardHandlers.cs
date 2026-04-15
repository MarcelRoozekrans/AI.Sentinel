using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.AspNetCore;

internal static class DashboardHandlers
{
    public static async Task IndexAsync(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/html; charset=utf-8";
        var html = ReadEmbedded("index.html");
        await ctx.Response.WriteAsync(html);
    }

    public static async Task StatsAsync(HttpContext ctx)
    {
        var store = ctx.RequestServices.GetRequiredService<IAuditStore>();
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), ctx.RequestAborted))
            entries.Add(e);

        ctx.Response.ContentType = "text/html";
        var html = $"""
            <div class="stat-card">
              <div class="count">{entries.Count}</div>
              <div class="label">Total</div>
            </div>
            <div class="stat-card critical">
              <div class="count">{entries.Count(e => e.Severity == Severity.Critical)}</div>
              <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
              <div class="count">{entries.Count(e => e.Severity == Severity.High)}</div>
              <div class="label">High</div>
            </div>
            <div class="stat-card medium">
              <div class="count">{entries.Count(e => e.Severity == Severity.Medium)}</div>
              <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
              <div class="count">{entries.Count(e => e.Severity == Severity.Low)}</div>
              <div class="label">Low</div>
            </div>
            """;
        await ctx.Response.WriteAsync(html);
    }

    public static async Task LiveFeedAsync(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/html";
        var store = ctx.RequestServices.GetRequiredService<IAuditStore>();
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: 50), ctx.RequestAborted))
            entries.Add(e);

        var sb = new StringBuilder();
        foreach (var e in entries.OrderByDescending(x => x.Timestamp).Take(50))
        {
            var reason = e.Summary.Length > 60 ? e.Summary[..60] + "\u2026" : e.Summary;
            sb.AppendLine($"""
                <tr class="severity-{e.Severity.ToString().ToLowerInvariant()}">
                  <td>{e.Timestamp:HH:mm:ss}</td>
                  <td>{HtmlEncode(e.DetectorId)}</td>
                  <td><span class="badge {e.Severity.ToString().ToLowerInvariant()}">{e.Severity}</span></td>
                  <td title="{HtmlEncode(e.Summary)}">{HtmlEncode(reason)}</td>
                  <td class="hash">{e.Hash[..Math.Min(8, e.Hash.Length)]}</td>
                </tr>
                """);
        }

        await ctx.Response.WriteAsync(sb.ToString());
    }

    public static async Task TrsStreamAsync(HttpContext ctx)
    {
        ctx.Response.Headers["Content-Type"] = "text/event-stream";
        ctx.Response.Headers["Cache-Control"] = "no-cache";
        ctx.Response.Headers["X-Accel-Buffering"] = "no";

        var store = ctx.RequestServices.GetRequiredService<IAuditStore>();

        while (!ctx.RequestAborted.IsCancellationRequested)
        {
            try
            {
                var entries = new List<AuditEntry>();
                await foreach (var e in store.QueryAsync(new AuditQuery(), ctx.RequestAborted))
                    entries.Add(e);

                var scoreInputs = entries.Select(e => new ThreatRiskScore(e.Severity switch
                {
                    Severity.Critical => 100,
                    Severity.High     => 70,
                    Severity.Medium   => 40,
                    Severity.Low      => 15,
                    _                 => 0
                }));

                var trs = ThreatRiskScore.Aggregate(scoreInputs);
                var json = JsonSerializer.Serialize(new { value = trs.Value, stage = trs.Stage.ToString() });
                await ctx.Response.WriteAsync($"data: {json}\n\n", ctx.RequestAborted);
                await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
                await Task.Delay(2000, ctx.RequestAborted);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    private static readonly HashSet<string> AllowedStaticFiles =
        new(StringComparer.OrdinalIgnoreCase) { "sentinel.css" };

    public static Task StaticFileAsync(HttpContext ctx)
    {
        var file = (string?)ctx.Request.RouteValues["file"] ?? "";

        if (!AllowedStaticFiles.Contains(file))
        {
            ctx.Response.StatusCode = 404;
            return Task.CompletedTask;
        }

        var content = ReadEmbedded(file);
        if (string.IsNullOrEmpty(content))
        {
            ctx.Response.StatusCode = 404;
            return Task.CompletedTask;
        }
        ctx.Response.ContentType = file.EndsWith(".css") ? "text/css" : "application/javascript";
        return ctx.Response.WriteAsync(content);
    }

    private static string ReadEmbedded(string filename)
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(filename.Replace('/', '.').Replace('\\', '.'),
                StringComparison.OrdinalIgnoreCase));
        if (name is null) return string.Empty;
        using var stream = asm.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string HtmlEncode(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
