using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
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
        var filter  = (string?)ctx.Request.Query["filter"];
        var q       = (string?)ctx.Request.Query["q"];
        var session = (string?)ctx.Request.Query["session"];

        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: 50), ctx.RequestAborted).ConfigureAwait(false))
            entries.Add(e);

        var filtered = FilterAuditEntries(entries, filter, q, session).ToList();

        var sb = new StringBuilder();
        var ordered = filtered.OrderByDescending(x => x.Timestamp).Take(50).ToList();
        if (ordered.Count == 0)
        {
            var emptyMessage = (filter, q, session) switch
            {
                (null or "", null or "", null or "") => "No events yet — agents are quiet.",
                _                                      => "No events match this filter.",
            };
            sb.Append("<tr class=\"feed-empty\"><td colspan=\"6\">")
              .Append(emptyMessage)
              .AppendLine("</td></tr>");
            await ctx.Response.WriteAsync(sb.ToString()).ConfigureAwait(false);
            return;
        }
        foreach (ref readonly var e in CollectionsMarshal.AsSpan(ordered))
        {
            RenderFeedRow(sb, e);
        }

        await ctx.Response.WriteAsync(sb.ToString()).ConfigureAwait(false);
    }

    /// <summary>Renders a single &lt;tr&gt; row for /api/feed. Extracted from
    /// <see cref="LiveFeedAsync"/> to keep the handler under MA0051's 60-line cap once
    /// the Session column was added in Dashboard 2.0.</summary>
    private static void RenderFeedRow(StringBuilder sb, AuditEntry e)
    {
        var reason = e.Summary.Length > 60 ? e.Summary[..60] + "\u2026" : e.Summary;
        var severityLower = e.Severity.ToString().ToLowerInvariant();
        var ts = e.Timestamp.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
        var hashPrefix = e.Hash[..Math.Min(8, e.Hash.Length)];
        var isAuthz = string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal);
        sb.Append("<tr class=\"severity-")
          .Append(severityLower);
        if (isAuthz)
            sb.Append(" audit-row-authz");
        sb.AppendLine("\">")
          .Append("  <td>").Append(ts).AppendLine("</td>")
          .Append("  <td>").Append(HtmlEncode(e.DetectorId)).AppendLine("</td>")
          .Append("  <td><span class=\"badge ").Append(severityLower).Append("\">").Append(e.Severity.ToString()).AppendLine("</span></td>")
          .Append("  <td title=\"").Append(HtmlEncode(e.Summary)).Append("\">");
        if (isAuthz)
        {
            sb.Append("<span class=\"badge code\">")
              .Append(HtmlEncode(e.PolicyCode ?? SentinelDenyCodes.PolicyDenied))
              .Append("</span> ");
        }
        sb.Append(HtmlEncode(reason)).AppendLine("</td>");
        sb.Append("  <td class=\"session\">");
        if (!string.IsNullOrEmpty(e.SessionId))
        {
            var sessionShort = e.SessionId.Length > 8 ? e.SessionId[..8] : e.SessionId;
            sb.Append("<a href=\"#\" class=\"session-link\" data-session=\"")
              .Append(HtmlEncode(e.SessionId))
              .Append("\" title=\"")
              .Append(HtmlEncode(e.SessionId))
              .Append("\">")
              .Append(HtmlEncode(sessionShort))
              .Append("</a>");
        }
        else
        {
            sb.Append("\u2014");
        }
        sb.AppendLine("</td>")
          .Append("  <td class=\"hash\">").Append(hashPrefix).AppendLine("</td>")
          .AppendLine("</tr>");
    }

    /// <summary>Maps a category name from a chip filter (e.g. "security", "hallucination") to the
    /// matching DetectorId prefix. Unknown / empty / null category returns true (no filtering).</summary>
    internal static bool IsInCategory(string detectorId, string? category) => category switch
    {
        "security"      => detectorId.StartsWith("SEC-",   StringComparison.Ordinal),
        "hallucination" => detectorId.StartsWith("HAL-",   StringComparison.Ordinal),
        "operational"   => detectorId.StartsWith("OPS-",   StringComparison.Ordinal),
        "authorization" or "authz" => detectorId.StartsWith("AUTHZ-", StringComparison.Ordinal),  // 'authz' = legacy alias
        _               => true,
    };

    /// <summary>Single-source-of-truth filter pipeline used by /api/feed and /api/export.ndjson.
    /// /api/trend deliberately does NOT use this — it always renders the global trend (design D4).
    /// All three filters AND together: chips ∧ session ∧ search.</summary>
    /// <remarks>Returns a lazy IEnumerable; callers that enumerate more than once should
    /// materialise via .ToList() to avoid re-evaluating predicates.</remarks>
    internal static IEnumerable<AuditEntry> FilterAuditEntries(
        IEnumerable<AuditEntry> entries, string? category, string? q, string? session)
    {
        // Order is deliberate: cheap+selective filters (category, session) first,
        // expensive Contains() last so it runs on the smallest residual set.
        if (!string.IsNullOrEmpty(category))
            entries = entries.Where(e => IsInCategory(e.DetectorId, category));
        if (!string.IsNullOrEmpty(session))
            entries = entries.Where(e => string.Equals(e.SessionId, session, StringComparison.Ordinal));
        if (!string.IsNullOrEmpty(q))
            entries = entries.Where(e => e.Summary.Contains(q, StringComparison.OrdinalIgnoreCase));
        return entries;
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
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");

    /// <summary>
    /// GET /api/approvals — HTML fragment listing pending approvals. Renders a table for
    /// stores that own approval state (InMemory / Sqlite — implement IApprovalAdmin).
    /// For external-state stores like EntraPim, renders a single "Approve at PIM portal" row.
    /// </summary>
    public static async Task ListApprovalsAsync(HttpContext ctx)
    {
        var store = ctx.RequestServices.GetService<IApprovalStore>();
        if (store is null)
        {
            ctx.Response.ContentType = "text/html";
            await ctx.Response.WriteAsync("""<tr class="approvals-empty"><td colspan="4">No approval store configured.</td></tr>""").ConfigureAwait(false);
            return;
        }

        if (store is not IApprovalAdmin admin)
        {
            // EntraPim path — admin actions happen in the external system.
            ctx.Response.ContentType = "text/html";
            await ctx.Response.WriteAsync("""<tr class="approvals-external"><td colspan="4">Approvals are managed externally (Entra PIM portal). Use the Azure portal to approve or deny.</td></tr>""").ConfigureAwait(false);
            return;
        }

        var sb = new StringBuilder();
        var any = false;
        await foreach (var pending in admin.ListPendingAsync(ctx.RequestAborted).ConfigureAwait(false))
        {
            any = true;
            var ts = pending.RequestedAt.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
            var requestIdEsc = HtmlEncode(pending.RequestId);
            // URL-encode the request id for path segments. IApprovalStore implementations are free
            // to mint IDs containing URL-special characters (?, #, /, %); HtmlEncode alone won't
            // escape those, so use Uri.EscapeDataString for the hx-post URL contexts.
            var requestIdUrl = Uri.EscapeDataString(pending.RequestId);
            sb.Append("<tr data-request-id=\"").Append(requestIdEsc).Append("\">")
              .Append("<td>").Append(ts).Append("</td>")
              .Append("<td>").Append(HtmlEncode(pending.CallerId)).Append("</td>")
              .Append("<td>").Append(HtmlEncode(pending.ToolName)).Append("</td>")
              .Append("<td class=\"actions\">")
              .Append("<button type=\"button\" class=\"btn-approve\" hx-post=\"api/approvals/").Append(requestIdUrl).Append("/approve\" hx-target=\"closest tr\" hx-swap=\"outerHTML swap:0.25s\">Approve</button>")
              .Append("<button type=\"button\" class=\"btn-deny\" hx-post=\"api/approvals/").Append(requestIdUrl).Append("/deny\" hx-target=\"closest tr\" hx-swap=\"outerHTML swap:0.25s\" hx-vals='{\"reason\":\"denied via dashboard\"}'>Deny</button>")
              .AppendLine("</td></tr>");
        }
        if (!any)
        {
            sb.Append("<tr class=\"approvals-empty\"><td colspan=\"4\">No pending approvals.</td></tr>");
        }

        ctx.Response.ContentType = "text/html";
        await ctx.Response.WriteAsync(sb.ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// POST /api/approvals/{id}/approve — flips a Pending request to Active. 200 + empty
    /// row HTML on success (so HTMX swaps the row out). 404 if the store doesn't expose
    /// IApprovalAdmin (e.g., EntraPim — should never receive POSTs in that mode).
    /// </summary>
    public static async Task ApproveAsync(HttpContext ctx)
    {
        // Fail closed: a misconfigured deployment that forgot to wrap the dashboard with auth
        // would otherwise silently record "anonymous" as the approver in the audit log forever.
        // Force a 401 so the operator notices and wires real authentication.
        if (ctx.User?.Identity?.IsAuthenticated != true)
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Authentication required to approve/deny. Wrap the dashboard with an auth middleware (see docs).").ConfigureAwait(false);
            return;
        }

        var requestId = (string?)ctx.Request.RouteValues["id"] ?? "";
        if (string.IsNullOrWhiteSpace(requestId))
        {
            ctx.Response.StatusCode = 400;
            return;
        }

        var store = ctx.RequestServices.GetService<IApprovalStore>();
        if (store is not IApprovalAdmin admin)
        {
            ctx.Response.StatusCode = 404;
            return;
        }

        // Authenticated but no Name (e.g., cert auth without subject extraction): "unknown"
        // is at least honest, vs. the previous "anonymous" which masked an auth misconfiguration.
        var approverId = ctx.User.Identity.Name ?? "unknown";
        await admin.ApproveAsync(requestId, approverId, note: null, ctx.RequestAborted).ConfigureAwait(false);

        // Return an empty row so HTMX removes the row from the table.
        ctx.Response.ContentType = "text/html";
        await ctx.Response.WriteAsync("").ConfigureAwait(false);
    }

    /// <summary>
    /// POST /api/approvals/{id}/deny — flips a Pending request to Denied. Reads `reason`
    /// from form/JSON body. Same response shape as ApproveAsync.
    /// </summary>
    public static async Task DenyAsync(HttpContext ctx)
    {
        // Fail closed: see ApproveAsync for rationale.
        if (ctx.User?.Identity?.IsAuthenticated != true)
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Authentication required to approve/deny. Wrap the dashboard with an auth middleware (see docs).").ConfigureAwait(false);
            return;
        }

        var requestId = (string?)ctx.Request.RouteValues["id"] ?? "";
        if (string.IsNullOrWhiteSpace(requestId))
        {
            ctx.Response.StatusCode = 400;
            return;
        }

        var store = ctx.RequestServices.GetService<IApprovalStore>();
        if (store is not IApprovalAdmin admin)
        {
            ctx.Response.StatusCode = 404;
            return;
        }

        string reason = "denied via dashboard";
        if (ctx.Request.HasFormContentType)
        {
            var form = await ctx.Request.ReadFormAsync(ctx.RequestAborted).ConfigureAwait(false);
            if (form.TryGetValue("reason", out var formReason))
            {
                var formReasonStr = formReason.ToString();
                if (!string.IsNullOrWhiteSpace(formReasonStr))
                {
                    reason = formReasonStr;
                }
            }
        }

        var approverId = ctx.User.Identity.Name ?? "unknown";
        await admin.DenyAsync(requestId, approverId, reason, ctx.RequestAborted).ConfigureAwait(false);

        ctx.Response.ContentType = "text/html";
        await ctx.Response.WriteAsync("").ConfigureAwait(false);
    }
}
