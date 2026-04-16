using System.Reflection;
using System.Runtime.InteropServices;
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
        await ctx.Response.WriteAsync(html).ConfigureAwait(false);
    }

    public static async Task StatsAsync(HttpContext ctx)
    {
        var store = ctx.RequestServices.GetRequiredService<IAuditStore>();
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), ctx.RequestAborted).ConfigureAwait(false))
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
        await ctx.Response.WriteAsync(html).ConfigureAwait(false);
    }

    public static async Task LiveFeedAsync(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/html";
        var store = ctx.RequestServices.GetRequiredService<IAuditStore>();
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: 50), ctx.RequestAborted).ConfigureAwait(false))
            entries.Add(e);

        var sb = new StringBuilder();
        var ordered = entries.OrderByDescending(x => x.Timestamp).Take(50).ToList();
        foreach (ref readonly var e in CollectionsMarshal.AsSpan(ordered))
        {
            var reason = e.Summary.Length > 60 ? e.Summary[..60] + "\u2026" : e.Summary;
            var severityLower = e.Severity.ToString().ToLowerInvariant();
            var ts = e.Timestamp.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
            var hashPrefix = e.Hash[..Math.Min(8, e.Hash.Length)];
            sb.Append("<tr class=\"severity-")
              .Append(severityLower)
              .AppendLine("\">")
              .Append("  <td>").Append(ts).AppendLine("</td>")
              .Append("  <td>").Append(HtmlEncode(e.DetectorId)).AppendLine("</td>")
              .Append("  <td><span class=\"badge ").Append(severityLower).Append("\">").Append(e.Severity.ToString()).AppendLine("</span></td>")
              .Append("  <td title=\"").Append(HtmlEncode(e.Summary)).Append("\">").Append(HtmlEncode(reason)).AppendLine("</td>")
              .Append("  <td class=\"hash\">").Append(hashPrefix).AppendLine("</td>")
              .AppendLine("</tr>");
        }

        await ctx.Response.WriteAsync(sb.ToString()).ConfigureAwait(false);
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
                await foreach (var e in store.QueryAsync(new AuditQuery(), ctx.RequestAborted).ConfigureAwait(false))
                    entries.Add(e);

                var scoreInputs = BuildScoreInputs(entries);
                var trs = ThreatRiskScore.Aggregate(scoreInputs);
                var json = JsonSerializer.Serialize(new { value = trs.Value, stage = trs.Stage.ToString() });
                await ctx.Response.WriteAsync($"data: {json}\n\n", ctx.RequestAborted).ConfigureAwait(false);
                await ctx.Response.Body.FlushAsync(ctx.RequestAborted).ConfigureAwait(false);
                await Task.Delay(2000, ctx.RequestAborted).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    private static List<ThreatRiskScore> BuildScoreInputs(List<AuditEntry> entries)
    {
        var result = new List<ThreatRiskScore>(entries.Count);
        for (int i = 0; i < entries.Count; i++)
        {
            result.Add(new ThreatRiskScore(entries[i].Severity switch
            {
                Severity.Critical => 100,
                Severity.High     => 70,
                Severity.Medium   => 40,
                Severity.Low      => 15,
                _                 => 0
            }));
        }
        return result;
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
        ctx.Response.ContentType = file.EndsWith(".css", StringComparison.OrdinalIgnoreCase) ? "text/css" : "application/javascript";
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
