using System.Text;
using T = AI.Sentinel.Cli.Report.ReportText;

namespace AI.Sentinel.Cli.Report;

/// <summary>Renders a <see cref="ComplianceReport"/> as Markdown. Every value read from the audit log is escaped.</summary>
internal static class MarkdownReportRenderer
{
    /// <summary>Renders the report.</summary>
    /// <param name="report">The report to render.</param>
    internal static string Render(ComplianceReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var md = new StringBuilder();

        md.Append("# ").AppendLine(T.Title).AppendLine();
        md.Append("> ").AppendLine(Escape(report.Disclaimer)).AppendLine();
        md.AppendLine("| | |").AppendLine("|---|---|");
        Row(md, T.Period, T.PeriodText(report));
        Row(md, T.Generated, T.Instant(report.GeneratedAt));
        md.Append("| ").Append(T.AuditFile).Append(" | ").Append(CodeSpan(report.AuditFilePath)).AppendLine(" |").AppendLine();

        Art12(md, report.Art12);
        Art14(md, report.Art14);
        Art10(md, report.Art10);
        Art50(md, report.Art50);
        Art5(md, report.Art5);
        Art15(md, report.Art15);

        return md.ToString();
    }

    private static void Art12(StringBuilder md, ComplianceReport.Art12Section art12)
    {
        Heading(md, T.Art12Title);
        md.Append("- ").Append(T.Chain).Append(": ").AppendLine(Escape(T.ChainStatus(art12)));
        md.Append("- ").Append(T.HeadTrimmed).Append(": ").AppendLine(T.YesNo(art12.HeadTrimmed));
        md.Append("- ").Append(T.EntriesInPeriod).Append(": ").AppendLine(T.Number(art12.EntriesInPeriod)).AppendLine();
        md.AppendLine(Escape(art12.ChainNote)).AppendLine();
        SubHeading(md, T.EntriesBySource);
        Counts(md, T.Source, T.Entries, art12.EntriesBySource, T.NoEntries);
    }

    private static void Art14(StringBuilder md, ComplianceReport.Art14Section art14)
    {
        Heading(md, T.Art14Title);
        md.Append("- ").Append(T.AuthorizationDenials).Append(": ").AppendLine(T.Number(art14.AuthorizationDenials));
        md.Append("- ").Append(T.ApprovalHolds).Append(": ").AppendLine(T.Number(art14.ApprovalHolds)).AppendLine();
        SubHeading(md, T.ApprovalDecisions);
        Counts(md, T.Outcome, T.Requests, art14.ApprovalRequestsByOutcome, T.NoApprovals);
    }

    private static void Art10(StringBuilder md, ComplianceReport.Art10Section art10)
    {
        Heading(md, T.Art10Title);
        SubHeading(md, T.RedactionsByType);
        Counts(md, T.EntityType, T.Redacted, art10.RedactionsByType, T.NoRedactions);
        md.AppendLine(Escape(T.FallbackLine(art10.FallbackEntries))).AppendLine();
    }

    private static void Art50(StringBuilder md, ComplianceReport.Art50Section art50)
    {
        Heading(md, T.Art50Title);
        if (art50.DisclosedSessions == 0)
        {
            md.AppendLine(T.NoDisclosures).AppendLine();
            return;
        }
        md.Append("- ").Append(T.ConversationsDisclosed).Append(": ").AppendLine(T.Number(art50.DisclosedSessions)).AppendLine();
    }

    private static void Art5(StringBuilder md, ComplianceReport.Art5Section art5)
    {
        Heading(md, T.Art5Title);
        if (!art5.AnyDetections)
        {
            md.AppendLine(Escape(art5.Note ?? T.NoDetections)).AppendLine();
            return;
        }
        Detections(md, art5.Detections);
    }

    private static void Art15(StringBuilder md, ComplianceReport.Art15Section art15)
    {
        Heading(md, T.Art15Title);
        if (art15.Detections.Count == 0)
        {
            md.AppendLine(T.NoDetections).AppendLine();
            return;
        }
        Detections(md, art15.Detections);
        SubHeading(md, T.TopDetectors);
        md.Append("| ").Append(T.Detector).Append(" | ").Append(T.Detections).AppendLine(" |").AppendLine("|---|---:|");
        foreach (var top in art15.TopDetectors)
        {
            md.Append("| ").Append(Escape(top.DetectorId)).Append(" | ").Append(T.Number(top.Count)).AppendLine(" |");
        }
        md.AppendLine();
    }

    private static void Detections(StringBuilder md, IReadOnlyList<ComplianceReport.DetectionCount> detections)
    {
        md.Append("| ").Append(T.Detector).Append(" | ").Append(T.Severity).Append(" | ").Append(T.Detections).AppendLine(" |")
          .AppendLine("|---|---|---:|");
        foreach (var d in detections)
        {
            md.Append("| ").Append(Escape(d.DetectorId)).Append(" | ").Append(d.Severity.ToString())
              .Append(" | ").Append(T.Number(d.Count)).AppendLine(" |");
        }
        md.AppendLine();
    }

    private static void Counts(StringBuilder md, string keyHeader, string countHeader, IReadOnlyDictionary<string, int> counts, string empty)
    {
        if (counts.Count == 0)
        {
            md.AppendLine(empty).AppendLine();
            return;
        }
        md.Append("| ").Append(keyHeader).Append(" | ").Append(countHeader).AppendLine(" |").AppendLine("|---|---:|");
        foreach (var (key, count) in counts)
        {
            md.Append("| ").Append(Escape(key)).Append(" | ").Append(T.Number(count)).AppendLine(" |");
        }
        md.AppendLine();
    }

    private static void Row(StringBuilder md, string label, string value) =>
        md.Append("| ").Append(label).Append(" | ").Append(Escape(value)).AppendLine(" |");

    private static void Heading(StringBuilder md, string title) => md.Append("## ").AppendLine(title).AppendLine();

    private static void SubHeading(StringBuilder md, string title) => md.Append("### ").AppendLine(title).AppendLine();

    /// <summary>Escapes Markdown punctuation that could change the layout, and flattens line breaks.</summary>
    internal static string Escape(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\' or '`' or '*' or '_' or '[' or ']' or '<' or '>' or '|' or '&' or '#' or '!':
                    sb.Append('\\').Append(c);
                    break;
                case '\r' or '\n':
                    sb.Append(' ');
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    /// <summary>A code span whose fence is longer than any backtick run in the value, so the value shows verbatim.</summary>
    private static string CodeSpan(string value)
    {
        var flat = value.Replace('\r', ' ').Replace('\n', ' ');
        var longest = 0;
        var run = 0;
        foreach (var c in flat)
        {
            run = c == '`' ? run + 1 : 0;
            longest = Math.Max(longest, run);
        }
        var fence = new string('`', longest + 1);
        var pad = flat.StartsWith('`') || flat.EndsWith('`') ? " " : string.Empty;
        return fence + pad + flat.Replace("|", "\\|", StringComparison.Ordinal) + pad + fence;
    }
}
