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
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;

namespace AI.Sentinel.AspNetCore;

internal static class DashboardHandlers
{
    public static async Task IndexAsync(HttpContext ctx)
    {
        // The page loads its panels and stylesheet through relative URLs, which only resolve
        // under the prefix when the URL ends in a slash.
        if (!ctx.Request.Path.HasValue || !ctx.Request.Path.Value!.EndsWith('/'))
        {
            ctx.Response.Redirect(ctx.Request.PathBase + ctx.Request.Path + "/" + ctx.Request.QueryString);
            return;
        }

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

        // Informational entries are evidence, not threats: they stay out of every tile.
        entries.RemoveAll(AuditEntryKinds.IsInformational);

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
        var filter = (string?)ctx.Request.Query["filter"];
        var q = (string?)ctx.Request.Query["q"];
        var session = (string?)ctx.Request.Query["session"];
        var source = (string?)ctx.Request.Query["source"];

        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { PageSize = 50, Reverse = true, SessionId = session, Source = source }, ctx.RequestAborted).ConfigureAwait(false))
            entries.Add(e);

        var filtered = FilterAuditEntries(entries, filter, q, session, source).ToList();

        var sb = new StringBuilder();
        var ordered = filtered.OrderByDescending(x => x.Timestamp).Take(50).ToList();
        if (ordered.Count == 0)
        {
            var emptyMessage = (filter, q, session, source) switch
            {
                (null or "", null or "", null or "", null or "") => "No events yet — agents are quiet.",
                _ => "No events match this filter.",
            };
            sb.Append("<tr class=\"feed-empty\"><td colspan=\"7\">")
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
        var (severityLower, severityLabel) = BadgeFor(e);
        var ts = e.Timestamp.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
        var hashPrefix = e.Hash[..Math.Min(8, e.Hash.Length)];
        var isAuthz = string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal);
        sb.Append("<tr class=\"severity-")
          .Append(severityLower);
        if (isAuthz)
            sb.Append(" audit-row-authz");
        sb.AppendLine("\">")
          .Append("  <td>").Append(ts).AppendLine("</td>")
          .Append("  <td>").Append(HtmlEncode(e.DetectorId)).AppendLine("</td>");
        AppendSourceCell(sb, e.Source);
        sb.Append("  <td><span class=\"badge ").Append(severityLower).Append("\">").Append(severityLabel).AppendLine("</span></td>")
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
            sb.Append("<a href=\"#\" class=\"session-link filter-link\" data-filter-key=\"session\" data-filter-value=\"")
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

    /// <summary>Renders the Source cell: a clickable filter link, or an em dash for in-process
    /// entries that carry no source.</summary>
    private static void AppendSourceCell(StringBuilder sb, string? source)
    {
        sb.Append("  <td class=\"source\">");
        if (!string.IsNullOrEmpty(source))
        {
            sb.Append("<a href=\"#\" class=\"source-link filter-link\" data-filter-key=\"source\" data-filter-value=\"")
              .Append(HtmlEncode(source))
              .Append("\" title=\"Filter by source\">")
              .Append(HtmlEncode(source))
              .Append("</a>");
        }
        else
        {
            sb.Append("\u2014");
        }
        sb.AppendLine("</td>");
    }

    /// <summary>Badge css class and label of a feed row: the informational kind, or the severity for a detection.</summary>
    private static (string Css, string Label) BadgeFor(AuditEntry e)
    {
        if (AuditEntryKinds.IsRedaction(e))
            return ("redacted", "Redacted");
        if (AuditEntryKinds.IsDisclosure(e))
            return ("disclosed", "Disclosed");
        if (AuditEntryKinds.IsApproval(e))
            return ("approval", "Approval");
        if (AuditEntryKinds.IsInformational(e))
            return ("informational", "Info");
        return (e.Severity.ToString().ToLowerInvariant(), e.Severity.ToString());
    }

    /// <summary>Maps a category name from a chip filter (e.g. "security", "hallucination") to the
    /// matching DetectorId prefix. Unknown / empty / null category returns true (no filtering).</summary>
    internal static bool IsInCategory(string detectorId, string? category) => category switch
    {
        "security" => detectorId.StartsWith("SEC-", StringComparison.Ordinal),
        "hallucination" => detectorId.StartsWith("HAL-", StringComparison.Ordinal),
        "operational" => detectorId.StartsWith("OPS-", StringComparison.Ordinal),
        "compliance" => detectorId.StartsWith("CMP-", StringComparison.Ordinal),
        "authorization" or "authz" => detectorId.StartsWith("AUTHZ-", StringComparison.Ordinal),  // 'authz' = legacy alias
        _ => true,
    };

    /// <summary>True when <paramref name="e"/> belongs under the chip <paramref name="category"/>. The Redacted,
    /// Disclosed and Approvals chips list only their own kind of informational entry; a category chip lists only
    /// detections, so an informational entry never appears under Security even though a redaction's detector id
    /// starts with SEC-. An unknown category filters nothing.</summary>
    private static bool MatchesChip(AuditEntry e, string category)
    {
        if (string.Equals(category, "redacted", StringComparison.Ordinal))
            return AuditEntryKinds.IsRedaction(e);
        if (string.Equals(category, "disclosed", StringComparison.Ordinal))
            return AuditEntryKinds.IsDisclosure(e);
        if (string.Equals(category, "approval", StringComparison.Ordinal))
            return AuditEntryKinds.IsApproval(e);
        if (!IsKnownCategory(category))
            return true;
        return !AuditEntryKinds.IsInformational(e) && IsInCategory(e.DetectorId, category);
    }

    private static bool IsKnownCategory(string category) =>
        category is "security" or "hallucination" or "operational" or "compliance" or "authorization" or "authz";

    /// <summary>Single-source-of-truth filter pipeline used by /api/feed and /api/export.ndjson.
    /// /api/trend deliberately does NOT use this — it always renders the global trend (design D4).
    /// All four filters AND together: chips ∧ session ∧ source ∧ search.</summary>
    /// <remarks>Returns a lazy IEnumerable; callers that enumerate more than once should
    /// materialise via .ToList() to avoid re-evaluating predicates.</remarks>
    internal static IEnumerable<AuditEntry> FilterAuditEntries(
        IEnumerable<AuditEntry> entries, string? category, string? q, string? session, string? source)
    {
        // Order is deliberate: cheap+selective filters (category, session) first,
        // expensive Contains() last so it runs on the smallest residual set.
        if (!string.IsNullOrEmpty(category))
            entries = entries.Where(e => MatchesChip(e, category));
        if (!string.IsNullOrEmpty(session))
            entries = entries.Where(e => string.Equals(e.SessionId, session, StringComparison.Ordinal));
        if (!string.IsNullOrEmpty(source))
            entries = entries.Where(e => string.Equals(e.Source, source, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(q))
            entries = entries.Where(e => e.Summary.Contains(q, StringComparison.OrdinalIgnoreCase));
        return entries;
    }

    /// <summary>
    /// GET /api/trend — 30 buckets × 30s = 15-min severity trend rendered as inline SVG.
    /// Per design D4 this endpoint deliberately ignores the feed filters (chips/search/session) —
    /// it is a global dashboard signal, so callers always see the whole-system picture.
    /// </summary>
    public static async Task TrendAsync(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/html";
        var store = ctx.RequestServices.GetRequiredService<IAuditStore>();

        const int BucketSeconds = 30;
        const int BucketCount = 30;  // 30 × 30s = 15 minutes
        var bucketMs = BucketSeconds * 1000L;
        var now = DateTimeOffset.UtcNow;
        var windowStart = now.AddSeconds(-BucketSeconds * BucketCount);

        var buckets = new (int count, int maxSev)[BucketCount];
        await foreach (var e in store.QueryAsync(
            new AuditQuery { From = windowStart, PageSize = 10000 },
            ctx.RequestAborted).ConfigureAwait(false))
        {
            if (e.Timestamp < windowStart || AuditEntryKinds.IsInformational(e)) continue;
            var idx = (int)((e.Timestamp - windowStart).TotalMilliseconds / bucketMs);
            if (idx < 0 || idx >= BucketCount) continue;
            buckets[idx].count++;
            var sev = (int)e.Severity;
            if (sev > buckets[idx].maxSev) buckets[idx].maxSev = sev;
        }

        var sb = new StringBuilder();
        RenderTrendSvg(sb, buckets);
        await ctx.Response.WriteAsync(sb.ToString()).ConfigureAwait(false);
    }

    private static void RenderTrendSvg(StringBuilder sb, (int count, int maxSev)[] buckets)
    {
        const int Width = 600;
        const int Height = 100;
        const int PadTop = 8, PadBottom = 16, PadLeft = 24, PadRight = 8;
        var plotW = Width - PadLeft - PadRight;
        var plotH = Height - PadTop - PadBottom;
        var rawMax = buckets.Max(b => b.count);
        var maxCount = Math.Max(1, rawMax);  // used for Y-scaling only — avoid divide by zero
        var maxSevOverall = buckets.Max(b => b.maxSev);

        string stroke = maxSevOverall switch
        {
            >= 4 => "#ef4444",  // critical → red
            3 => "#f97316",  // high → orange
            2 => "#eab308",  // medium → amber
            1 => "#22c55e",  // low → green
            _ => "#475569",  // none / no data → muted
        };

        sb.Append("<svg viewBox=\"0 0 ").Append(Width).Append(' ').Append(Height)
          .Append("\" class=\"trend-chart\" role=\"img\" aria-label=\"Severity trend, last 15 minutes\" xmlns=\"http://www.w3.org/2000/svg\">");

        // Plot area background grid (just a baseline)
        sb.Append("<line x1=\"").Append(PadLeft).Append("\" y1=\"").Append(Height - PadBottom)
          .Append("\" x2=\"").Append(Width - PadRight).Append("\" y2=\"").Append(Height - PadBottom)
          .Append("\" stroke=\"#334155\" stroke-width=\"1\"/>");

        // Path
        sb.Append("<path d=\"M");
        for (var i = 0; i < buckets.Length; i++)
        {
            var x = PadLeft + (i * plotW / (buckets.Length - 1));
            var y = (Height - PadBottom) - (buckets[i].count * plotH / maxCount);
            if (i > 0) sb.Append(" L");
            sb.Append(x).Append(',').Append(y);
        }
        sb.Append("\" fill=\"none\" stroke=\"").Append(stroke).Append("\" stroke-width=\"2\" stroke-linejoin=\"round\"/>");

        // Y-axis label (max count)
        sb.Append("<text x=\"4\" y=\"").Append(PadTop + 8).Append("\" font-size=\"9\" fill=\"#94a3b8\">").Append(rawMax).Append("</text>");
        sb.Append("<text x=\"4\" y=\"").Append(Height - PadBottom + 4).Append("\" font-size=\"9\" fill=\"#94a3b8\">0</text>");
        // X-axis labels (now / 15m ago)
        sb.Append("<text x=\"").Append(PadLeft).Append("\" y=\"").Append(Height - 2).Append("\" font-size=\"9\" fill=\"#94a3b8\">15m ago</text>");
        sb.Append("<text x=\"").Append(Width - PadRight - 20).Append("\" y=\"").Append(Height - 2).Append("\" font-size=\"9\" fill=\"#94a3b8\">now</text>");

        sb.Append("</svg>");
    }

    /// <summary>Maximum entries returned by the NDJSON export endpoint per request. Any
    /// query that would return more is truncated; the X-Sentinel-Truncated response header
    /// signals this to the client.</summary>
    private const int ExportPageCap = 10_000;

    /// <summary>Streams the current filtered audit log as NDJSON for download. Honours
    /// chips ∧ session ∧ source ∧ search filters from the live feed.</summary>
    /// <remarks>
    /// Capped at <see cref="ExportPageCap"/> entries per request. When the cap is hit, the
    /// response includes <c>X-Sentinel-Truncated: true</c> so consumers can detect partial
    /// exports without re-counting. Header convention: <c>X-Sentinel-*</c> (matches the
    /// dashboard URL prefix); value is the literal string <c>"true"</c> when set, header
    /// absent otherwise. Future <c>X-Sentinel-*</c> headers should follow this pattern.
    /// </remarks>
    public static async Task ExportNdjsonAsync(HttpContext ctx)
    {
        var filter = (string?)ctx.Request.Query["filter"];
        var q = (string?)ctx.Request.Query["q"];
        var session = (string?)ctx.Request.Query["session"];
        var source = (string?)ctx.Request.Query["source"];

        var store = ctx.RequestServices.GetRequiredService<IAuditStore>();
        var entries = new List<AuditEntry>();
        // Reverse = true → store returns newest-first. With PageSize = ExportPageCap we get the
        // most recent entries instead of the oldest (which would silently omit all recent
        // activity on long-running stores). Session is pushed down to the store so an
        // old-session export can't be silently emptied by newer entries filling the cap.
        await foreach (var e in store.QueryAsync(
            new AuditQuery { PageSize = ExportPageCap, Reverse = true, SessionId = session, Source = source },
            ctx.RequestAborted).ConfigureAwait(false))
            entries.Add(e);

        // Session is now pushed down to the store; FilterAuditEntries only handles
        // the in-memory chip+q filters. Truncation (entries.Count >= ExportPageCap)
        // thus reflects "the store hit its cap for this session+severity selection."
        var filtered = FilterAuditEntries(entries, filter, q, session: null, source: null)
            .OrderBy(e => e.Timestamp)
            .ToArray();

        WriteExportHeaders(ctx, entries.Count);

        // Cache the newline byte to avoid per-entry allocation.
        var newline = "\n"u8.ToArray();
        foreach (var entry in filtered)
        {
            await JsonSerializer.SerializeAsync(ctx.Response.Body, entry, AuditJsonContext.Default.AuditEntry, ctx.RequestAborted).ConfigureAwait(false);
            await ctx.Response.Body.WriteAsync(newline, ctx.RequestAborted).ConfigureAwait(false);
        }
    }

    private static void WriteExportHeaders(HttpContext ctx, int totalEntries)
    {
        ctx.Response.ContentType = "application/x-ndjson; charset=utf-8";
        var filename = "audit-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture) + ".ndjson";
        ctx.Response.Headers.ContentDisposition = $"attachment; filename=\"{filename}\"";
        // X-Sentinel-Truncated: emitted when the store-level cap was hit. With session
        // push-down (Phase 5 polish), this is precise: it means "there are older entries
        // matching your session+severity selection that we didn't return." Without
        // session push-down, this would over-fire whenever the store had >ExportPageCap
        // entries regardless of session match.
        if (totalEntries >= ExportPageCap)
            ctx.Response.Headers["X-Sentinel-Truncated"] = "true";
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

    internal static List<ThreatRiskScore> BuildScoreInputs(List<AuditEntry> entries)
    {
        var result = new List<ThreatRiskScore>(entries.Count);
        for (int i = 0; i < entries.Count; i++)
        {
            // An informational entry scores 0 and would dilute the average of real detections.
            if (AuditEntryKinds.IsInformational(entries[i])) continue;
            result.Add(new ThreatRiskScore(entries[i].Severity switch
            {
                Severity.Critical => 100,
                Severity.High => 70,
                Severity.Medium => 40,
                Severity.Low => 15,
                _ => 0
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

    private const string ExternalMessage = "Approvals are managed externally (Entra PIM portal). Use the Azure portal to approve or deny.";

    private static string HtmlEncode(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");

    /// <summary>
    /// GET /api/approvals — HTML fragment listing pending approvals. Renders a table for
    /// stores that own approval state (InMemory / Sqlite — implement IApprovalAdmin).
    /// For external-state stores like EntraPim, renders a single "Approve at PIM portal" row.
    /// </summary>
    public static async Task ListApprovalsAsync(HttpContext ctx)
    {
        var store = ApprovalStoreAuditing.Resolve(ctx.RequestServices);
        if (store is null && ctx.RequestServices.GetService<ExternalApprovalPortal>() is null)
        {
            ctx.Response.ContentType = "text/html";
            await ctx.Response.WriteAsync("""<tr class="approvals-empty"><td colspan="4">No approval store configured.</td></tr>""").ConfigureAwait(false);
            return;
        }

        if (store is not IApprovalAdmin admin)
        {
            // EntraPim path: admin actions happen in the external system.
            ctx.Response.ContentType = "text/html";
            await ctx.Response.WriteAsync($"""<tr class="approvals-external"><td colspan="4">{ExternalMessage}</td></tr>""").ConfigureAwait(false);
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
              .Append("<td><a href=\"approvals/").Append(requestIdUrl).Append("\">").Append(ts).Append("</a></td>")
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
    /// GET /approvals/{id}: one pending request with its justification and redacted arguments,
    /// and Approve / Deny buttons that post to the existing endpoints. The page sits one segment
    /// below the prefix, so every URL is relative to <c>../</c>. Never cached: it shows live state.
    /// </summary>
    public static async Task ApprovalPageAsync(HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        // The page holds approval buttons: never let another site frame it.
        ctx.Response.Headers.XFrameOptions = "DENY";
        ctx.Response.Headers.ContentSecurityPolicy = "frame-ancestors 'none'";
        ctx.Response.ContentType = "text/html; charset=utf-8";

        var store = ApprovalStoreAuditing.Resolve(ctx.RequestServices);
        if (store is null && ctx.RequestServices.GetService<ExternalApprovalPortal>() is null)
        {
            ctx.Response.StatusCode = 404;
            await ctx.Response.WriteAsync(PageShell("Approval", "<p class=\"approval-note\">No approval store configured.</p>")).ConfigureAwait(false);
            return;
        }

        if (store is not IApprovalAdmin admin)
        {
            await ctx.Response.WriteAsync(PageShell("Approval", $"<p class=\"approval-note\">{ExternalMessage}</p>")).ConfigureAwait(false);
            return;
        }

        var requestId = RequestIdOf(ctx, trailingSegments: 0);
        PendingRequest? found = null;
        await foreach (var pending in admin.ListPendingAsync(ctx.RequestAborted).ConfigureAwait(false))
        {
            if (string.Equals(pending.RequestId, requestId, StringComparison.Ordinal))
            {
                found = pending;
                break;
            }
        }

        if (found is null)
        {
            await ctx.Response.WriteAsync(PageShell("Approval",
                "<p class=\"approval-note\">This request is no longer pending. It was already decided, or it expired.</p>")).ConfigureAwait(false);
            return;
        }

        await ctx.Response.WriteAsync(PageShell("Approval: " + found.ToolName, RenderRequest(found))).ConfigureAwait(false);
    }

    private static string RenderRequest(PendingRequest found)
    {
        var idUrl = Uri.EscapeDataString(found.RequestId);
        var sb = new StringBuilder();
        sb.AppendLine("<dl class=\"approval-fields\">")
          .Append("<dt>Tool</dt><dd>").Append(HtmlEncode(found.ToolName)).AppendLine("</dd>")
          .Append("<dt>Caller</dt><dd>").Append(HtmlEncode(found.CallerId)).AppendLine("</dd>")
          .Append("<dt>Policy</dt><dd>").Append(HtmlEncode(found.PolicyName)).AppendLine("</dd>")
          .Append("<dt>Requested at</dt><dd>")
          .Append(found.RequestedAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture))
          .AppendLine("</dd>");
        if (!string.IsNullOrWhiteSpace(found.Justification))
        {
            sb.Append("<dt>Justification</dt><dd>").Append(HtmlEncode(found.Justification)).AppendLine("</dd>");
        }
        sb.AppendLine("</dl>");

        if (found.Args.ValueKind != JsonValueKind.Undefined)
        {
            // Same redaction as the approval notifications: credentials and PII never reach the page.
            var session = new RedactionSession([new CredentialExposureDetector(), new PiiLeakageDetector()]);
            var redacted = session.RedactJsonValues(found.Args);
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            {
                redacted.WriteTo(writer);
            }
            sb.Append("<h2>Arguments</h2><pre class=\"approval-args\">")
              .Append(HtmlEncode(Encoding.UTF8.GetString(buffer.ToArray())))
              .AppendLine("</pre>");
        }

        sb.Append("<div id=\"approval-actions\" class=\"approval-actions\">")
          .Append("<button type=\"button\" class=\"btn-approve\" hx-post=\"../api/approvals/").Append(idUrl)
          .Append("/approve\" hx-swap=\"none\" hx-on::after-request=\"if (event.detail.successful) { this.parentElement.textContent = 'Approved.'; } else { document.getElementById('approval-status').textContent = 'Could not record the decision.'; }\">Approve</button>")
          .Append("<input type=\"text\" name=\"reason\" id=\"deny-reason\" placeholder=\"Reason for denying (optional)\" maxlength=\"500\">")
          .Append("<button type=\"button\" class=\"btn-deny\" hx-post=\"../api/approvals/").Append(idUrl)
          .Append("/deny\" hx-include=\"#deny-reason\" hx-swap=\"none\" hx-on::after-request=\"if (event.detail.successful) { this.parentElement.textContent = 'Denied.'; } else { document.getElementById('approval-status').textContent = 'Could not record the decision.'; }\">Deny</button>")
          .AppendLine("</div>")
          .AppendLine("<p id=\"approval-status\" class=\"approval-note\" role=\"status\"></p>");

        return sb.ToString();
    }

    /// <summary>
    /// The request id, decoded exactly once. Ids may contain %2F, ? and %, which hosts and routing
    /// decode inconsistently in route values, so take the {id} segment from the undecoded request
    /// target. <paramref name="trailingSegments"/> counts the segments after the id (0 for the page,
    /// 1 for approve and deny). Falls back to the route value when the host gives no raw target.
    /// </summary>
    private static string RequestIdOf(HttpContext ctx, int trailingSegments)
    {
        var raw = ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(raw))
        {
            var end = raw.IndexOf('?', StringComparison.Ordinal);
            var path = end >= 0 ? raw[..end] : raw;
            var segments = path.Split('/');
            var index = segments.Length - 1 - trailingSegments;
            if (index >= 0 && segments[index].Length > 0)
            {
                return Uri.UnescapeDataString(segments[index]);
            }
        }

        return (string?)ctx.Request.RouteValues["id"] ?? "";
    }

    private static string PageShell(string title, string body) =>
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n"
        + "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        + "  <title>" + HtmlEncode(title) + "</title>\n  <link rel=\"icon\" href=\"data:,\">\n"
        + "  <script src=\"https://unpkg.com/htmx.org@2.0.4\" integrity=\"sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+\" crossorigin=\"anonymous\"></script>\n"
        + "  <link rel=\"stylesheet\" href=\"../static/sentinel.css\">\n</head>\n<body>\n"
        + "<main class=\"approval-page\">\n<a class=\"approval-back\" href=\"../\">&larr; Dashboard</a>\n"
        + "<h1>" + HtmlEncode(title) + "</h1>\n" + body + "\n</main>\n</body>\n</html>\n";

    /// <summary>
    /// True when a browser marked the request as cross-site. Cookie-based forward auth sends the
    /// session cookie on a cross-site POST, so authentication alone does not prove intent.
    /// Sec-Fetch-Site decides when present; otherwise Origin must match the request origin.
    /// Requests with neither header (scripts, curl) are not browser-driven and pass.
    /// </summary>
    private static bool IsCrossSite(HttpRequest request)
    {
        if (request.Headers.TryGetValue("Sec-Fetch-Site", out var site) && site.Count > 0)
        {
            var value = site.ToString();
            return !string.Equals(value, "same-origin", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(value, "none", StringComparison.OrdinalIgnoreCase);
        }

        if (request.Headers.TryGetValue("Origin", out var origin) && origin.Count > 0)
        {
            if (!Uri.TryCreate(origin.ToString(), UriKind.Absolute, out var originUri))
            {
                return true;   // includes the literal "null"
            }

            // Browsers send a bare origin; a path, query, fragment or userinfo means a forged header.
            if (!string.Equals(originUri.AbsolutePath, "/", StringComparison.Ordinal) || originUri.Query.Length > 0
                || originUri.Fragment.Length > 0 || originUri.UserInfo.Length > 0)
            {
                return true;
            }

            var host = request.Host;
            var expectedPort = host.Port ?? (string.Equals(request.Scheme, "https", StringComparison.OrdinalIgnoreCase) ? 443 : 80);
            return !string.Equals(originUri.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(originUri.Host, host.Host, StringComparison.OrdinalIgnoreCase)
                || originUri.Port != expectedPort;
        }

        return false;
    }

    /// <summary>
    /// POST /api/approvals/{id}/approve — flips a Pending request to Active. 200 + empty
    /// row HTML on success (so HTMX swaps the row out). 404 if the store doesn't expose
    /// IApprovalAdmin (e.g., EntraPim — should never receive POSTs in that mode).
    /// </summary>
    public static async Task ApproveAsync(HttpContext ctx)
    {
        if (IsCrossSite(ctx.Request))
        {
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsync("Cross-site approval requests are refused.").ConfigureAwait(false);
            return;
        }

        // Fail closed: a misconfigured deployment that forgot to wrap the dashboard with auth
        // would otherwise silently record "anonymous" as the approver in the audit log forever.
        // Force a 401 so the operator notices and wires real authentication.
        if (ctx.User?.Identity?.IsAuthenticated != true)
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Authentication required to approve/deny. Wrap the dashboard with an auth middleware (see docs).").ConfigureAwait(false);
            return;
        }

        var requestId = RequestIdOf(ctx, trailingSegments: 1);
        if (string.IsNullOrWhiteSpace(requestId))
        {
            ctx.Response.StatusCode = 400;
            return;
        }

        var store = ApprovalStoreAuditing.Resolve(ctx.RequestServices);
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
        if (IsCrossSite(ctx.Request))
        {
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsync("Cross-site approval requests are refused.").ConfigureAwait(false);
            return;
        }

        // Fail closed: see ApproveAsync for rationale.
        if (ctx.User?.Identity?.IsAuthenticated != true)
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Authentication required to approve/deny. Wrap the dashboard with an auth middleware (see docs).").ConfigureAwait(false);
            return;
        }

        var requestId = RequestIdOf(ctx, trailingSegments: 1);
        if (string.IsNullOrWhiteSpace(requestId))
        {
            ctx.Response.StatusCode = 400;
            return;
        }

        var store = ApprovalStoreAuditing.Resolve(ctx.RequestServices);
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
