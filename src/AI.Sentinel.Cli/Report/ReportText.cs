using System.Globalization;

namespace AI.Sentinel.Cli.Report;

/// <summary>The headings and sentences the Markdown and HTML renderers share, so both formats say the same thing.</summary>
internal static class ReportText
{
    internal const string Title = "AI.Sentinel compliance report";
    internal const string Art12Title = "Art. 12 Record keeping";
    internal const string Art14Title = "Art. 14 Human oversight";
    internal const string Art10Title = "Art. 10 Data minimisation and GDPR";
    internal const string Art50Title = "Art. 50 Transparency";
    internal const string Art5Title = "Art. 5 Prohibited practices";
    internal const string Art15Title = "Art. 15 Accuracy and robustness";

    internal const string NoEntries = "No entries in this period.";
    internal const string NoApprovals = "No approval decisions recorded in this period.";
    internal const string NoRedactions = "No redactions recorded in this period.";
    internal const string NoDisclosures = "No disclosures recorded in this period.";
    internal const string NoDetections = "No detections recorded in this period.";

    internal const string Period = "Period";
    internal const string Generated = "Generated";
    internal const string AuditFile = "Audit file";
    internal const string Chain = "Hash chain";
    internal const string HeadTrimmed = "Head trimmed";
    internal const string EntriesInPeriod = "Entries in period";
    internal const string EntriesBySource = "Entries by source";
    internal const string Source = "Source";
    internal const string Entries = "Entries";
    internal const string AuthorizationDenials = "Authorization denials";
    internal const string ApprovalDecisions = "Approval decisions";
    internal const string Outcome = "Outcome";
    internal const string Requests = "Requests";
    internal const string RedactionsByType = "Redactions by type";
    internal const string EntityType = "Entity type";
    internal const string Redacted = "Redacted";
    internal const string ConversationsDisclosed = "Conversations disclosed";
    internal const string Detector = "Detector";
    internal const string Severity = "Severity";
    internal const string Detections = "Detections";
    internal const string TopDetectors = "Top detectors";

    internal const string FallbackNote =
        "These detections are also counted under Art. 15, or under Art. 5 for a CMP- detector.";

    /// <summary>The fallback line: the count, and where those detections are also counted when there are any.</summary>
    /// <param name="count">Detections that wanted redaction and could not redact.</param>
    internal static string FallbackLine(int count) =>
        count == 0
            ? "Detections that could not be redacted: 0."
            : string.Create(CultureInfo.InvariantCulture, $"Detections that could not be redacted: {count}. ") + FallbackNote;

    /// <summary>The chain status sentence.</summary>
    /// <param name="art12">The record keeping section.</param>
    internal static string ChainStatus(ComplianceReport.Art12Section art12) =>
        art12.ChainIntact
            ? string.Create(CultureInfo.InvariantCulture, $"intact, {art12.EntriesChecked} entries verified.")
            : string.Create(CultureInfo.InvariantCulture,
                $"broken at entry {art12.FirstBrokenEntryId}, {art12.EntriesChecked} entries verified before the break.");

    /// <summary>A yes or no.</summary>
    /// <param name="value">The value.</param>
    internal static string YesNo(bool value) => value ? "yes" : "no";

    /// <summary>An instant as a UTC timestamp to the second.</summary>
    /// <param name="value">The instant.</param>
    internal static string Instant(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    /// <summary>The period, from and to.</summary>
    /// <param name="report">The report.</param>
    internal static string PeriodText(ComplianceReport report) => Instant(report.From) + " to " + Instant(report.To);

    /// <summary>A count.</summary>
    /// <param name="value">The count.</param>
    internal static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);
}
