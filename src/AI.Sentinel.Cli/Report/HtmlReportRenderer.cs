using System.Net;
using System.Text;
using T = AI.Sentinel.Cli.Report.ReportText;

namespace AI.Sentinel.Cli.Report;

/// <summary>
/// Renders a <see cref="ComplianceReport"/> as one self-contained HTML file: inline CSS in a light theme, no script
/// and no external reference. Every value is HTML-encoded, because detector ids and sources are data.
/// </summary>
internal static class HtmlReportRenderer
{
    private const string Style = """
        :root { color-scheme: light; }
        body { margin: 0; background: #ffffff; color: #1f2328; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
        main { max-width: 860px; margin: 0 auto; padding: 32px 16px 48px; }
        h1 { font-size: 1.6rem; margin: 0 0 16px; }
        h2 { font-size: 1.2rem; margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #d0d7de; }
        h3 { font-size: 1rem; margin: 16px 0 8px; }
        .disclaimer { margin: 0 0 16px; padding: 12px 16px; background: #fff8c5; border: 1px solid #d4a72c; border-radius: 6px; }
        table { border-collapse: collapse; margin: 8px 0 16px; }
        th, td { border: 1px solid #d0d7de; padding: 4px 12px; text-align: left; vertical-align: top; }
        th { background: #f6f8fa; }
        td.num { text-align: right; font-variant-numeric: tabular-nums; }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
        .empty { color: #59636e; font-style: italic; }
        .ok { color: #1a7f37; font-weight: 600; }
        .broken { color: #cf222e; font-weight: 600; }
        .note { color: #59636e; }
        """;

    /// <summary>Renders the report.</summary>
    /// <param name="report">The report to render.</param>
    internal static string Render(ComplianceReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var html = new StringBuilder();

        html.AppendLine("<!DOCTYPE html>")
            .AppendLine("<html lang=\"en\">")
            .AppendLine("<head>")
            .AppendLine("<meta charset=\"utf-8\">")
            .AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            .Append("<title>").Append(E(T.Title)).AppendLine("</title>")
            .Append("<style>").Append(Style).AppendLine("</style>")
            .AppendLine("</head>")
            .AppendLine("<body>")
            .AppendLine("<main>")
            .Append("<h1>").Append(E(T.Title)).AppendLine("</h1>")
            .Append("<p class=\"disclaimer\">").Append(E(report.Disclaimer)).AppendLine("</p>")
            .AppendLine("<table>");
        Row(html, T.Period, E(T.PeriodText(report)));
        Row(html, T.Generated, E(T.Instant(report.GeneratedAt)));
        Row(html, T.AuditFile, "<code>" + E(report.AuditFilePath) + "</code>");
        html.AppendLine("</table>");

        Art12(html, report.Art12);
        Art14(html, report.Art14);
        Art10(html, report.Art10);
        Art50(html, report.Art50);
        Art5(html, report.Art5);
        Art15(html, report.Art15);

        html.AppendLine("</main>").AppendLine("</body>").AppendLine("</html>");
        return html.ToString();
    }

    private static void Art12(StringBuilder html, ComplianceReport.Art12Section art12)
    {
        Heading(html, T.Art12Title);
        html.AppendLine("<table>");
        Row(html, T.Chain,
            "<span class=\"" + (art12.ChainIntact ? "ok" : "broken") + "\">" + E(T.ChainStatus(art12)) + "</span>");
        Row(html, T.HeadTrimmed, E(T.YesNo(art12.HeadTrimmed)));
        Row(html, T.EntriesInPeriod, E(T.Number(art12.EntriesInPeriod)));
        html.AppendLine("</table>");
        Paragraph(html, "note", art12.ChainNote);
        SubHeading(html, T.EntriesBySource);
        Counts(html, T.Source, T.Entries, art12.EntriesBySource, T.NoEntries);
    }

    private static void Art14(StringBuilder html, ComplianceReport.Art14Section art14)
    {
        Heading(html, T.Art14Title);
        html.AppendLine("<table>");
        Row(html, T.AuthorizationDenials, E(T.Number(art14.AuthorizationDenials)));
        Row(html, T.ApprovalHolds, E(T.Number(art14.ApprovalHolds)));
        html.AppendLine("</table>");
        SubHeading(html, T.ApprovalDecisions);
        Counts(html, T.Outcome, T.Requests, art14.ApprovalRequestsByOutcome, T.NoApprovals);
    }

    private static void Art10(StringBuilder html, ComplianceReport.Art10Section art10)
    {
        Heading(html, T.Art10Title);
        SubHeading(html, T.RedactionsByType);
        Counts(html, T.EntityType, T.Redacted, art10.RedactionsByType, T.NoRedactions);
        Paragraph(html, "note", T.FallbackLine(art10.FallbackEntries));
    }

    private static void Art50(StringBuilder html, ComplianceReport.Art50Section art50)
    {
        Heading(html, T.Art50Title);
        if (art50.DisclosedSessions == 0)
        {
            Paragraph(html, "empty", T.NoDisclosures);
            return;
        }
        html.AppendLine("<table>");
        Row(html, T.ConversationsDisclosed, E(T.Number(art50.DisclosedSessions)));
        html.AppendLine("</table>");
    }

    private static void Art5(StringBuilder html, ComplianceReport.Art5Section art5)
    {
        Heading(html, T.Art5Title);
        if (!art5.AnyDetections)
        {
            Paragraph(html, "empty", art5.Note ?? T.NoDetections);
            return;
        }
        Detections(html, art5.Detections);
    }

    private static void Art15(StringBuilder html, ComplianceReport.Art15Section art15)
    {
        Heading(html, T.Art15Title);
        if (art15.Detections.Count == 0)
        {
            Paragraph(html, "empty", T.NoDetections);
            return;
        }
        Detections(html, art15.Detections);
        SubHeading(html, T.TopDetectors);
        html.AppendLine("<table>")
            .Append("<tr><th>").Append(E(T.Detector)).Append("</th><th>").Append(E(T.Detections)).AppendLine("</th></tr>");
        foreach (var top in art15.TopDetectors)
        {
            html.Append("<tr><td>").Append(E(top.DetectorId)).Append("</td><td class=\"num\">")
                .Append(E(T.Number(top.Count))).AppendLine("</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void Detections(StringBuilder html, IReadOnlyList<ComplianceReport.DetectionCount> detections)
    {
        html.AppendLine("<table>")
            .Append("<tr><th>").Append(E(T.Detector)).Append("</th><th>").Append(E(T.Severity)).Append("</th><th>")
            .Append(E(T.Detections)).AppendLine("</th></tr>");
        foreach (var d in detections)
        {
            html.Append("<tr><td>").Append(E(d.DetectorId)).Append("</td><td>").Append(E(d.Severity.ToString()))
                .Append("</td><td class=\"num\">").Append(E(T.Number(d.Count))).AppendLine("</td></tr>");
        }
        html.AppendLine("</table>");
    }

    private static void Counts(StringBuilder html, string keyHeader, string countHeader, IReadOnlyDictionary<string, int> counts, string empty)
    {
        if (counts.Count == 0)
        {
            Paragraph(html, "empty", empty);
            return;
        }
        html.AppendLine("<table>")
            .Append("<tr><th>").Append(E(keyHeader)).Append("</th><th>").Append(E(countHeader)).AppendLine("</th></tr>");
        foreach (var (key, count) in counts)
        {
            html.Append("<tr><td>").Append(E(key)).Append("</td><td class=\"num\">").Append(E(T.Number(count))).AppendLine("</td></tr>");
        }
        html.AppendLine("</table>");
    }

    /// <summary>A header row; <paramref name="valueHtml"/> must already be encoded.</summary>
    private static void Row(StringBuilder html, string label, string valueHtml) =>
        html.Append("<tr><th>").Append(E(label)).Append("</th><td>").Append(valueHtml).AppendLine("</td></tr>");

    private static void Paragraph(StringBuilder html, string cssClass, string text) =>
        html.Append("<p class=\"").Append(cssClass).Append("\">").Append(E(text)).AppendLine("</p>");

    private static void Heading(StringBuilder html, string title) => html.Append("<h2>").Append(E(title)).AppendLine("</h2>");

    private static void SubHeading(StringBuilder html, string title) => html.Append("<h3>").Append(E(title)).AppendLine("</h3>");

    private static string E(string value) => WebUtility.HtmlEncode(value);
}
