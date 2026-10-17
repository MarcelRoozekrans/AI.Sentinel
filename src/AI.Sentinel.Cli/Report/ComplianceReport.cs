using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli.Report;

/// <summary>
/// The compliance report read from the audit log: totals only. It never holds a detection summary, a session id or a
/// caller id; the only text parsed out of summaries is the entity types of redactions, as counts.
/// </summary>
/// <param name="Schema">Version of the JSON shape.</param>
/// <param name="From">Start of the period.</param>
/// <param name="To">End of the period, inclusive, compared as a UTC instant.</param>
/// <param name="GeneratedAt">When the report was built.</param>
/// <param name="AuditFilePath">The audit file the report was read from.</param>
/// <param name="Disclaimer">What the report is and is not.</param>
/// <param name="Art12">Record keeping.</param>
/// <param name="Art14">Human oversight.</param>
/// <param name="Art10">Data minimisation.</param>
/// <param name="Art50">Transparency.</param>
/// <param name="Art5">Prohibited-practice detections.</param>
/// <param name="Art15">All other detections.</param>
internal sealed record ComplianceReport(
    int Schema,
    DateTimeOffset From,
    DateTimeOffset To,
    DateTimeOffset GeneratedAt,
    string AuditFilePath,
    string Disclaimer,
    ComplianceReport.Art12Section Art12,
    ComplianceReport.Art14Section Art14,
    ComplianceReport.Art10Section Art10,
    ComplianceReport.Art50Section Art50,
    ComplianceReport.Art5Section Art5,
    ComplianceReport.Art15Section Art15)
{
    /// <summary>The report's disclaimer.</summary>
    internal const string DisclaimerText =
        "This report summarises what AI.Sentinel recorded in its audit log. It is evidence to support an EU AI Act assessment, not a statement of compliance.";

    /// <summary>The chain note: the chain is global and a trimmed head verifies from the oldest retained entry.</summary>
    internal const string ChainNote =
        "The hash chain is verified over the whole audit file, oldest entry first, not only the period. When retention has trimmed the head of the file, the chain is verified from the oldest retained entry.";

    /// <summary>The Art. 5 note shown when nothing was detected.</summary>
    internal const string Art5NoDetectionsNote =
        "No Art. 5 detections were recorded. The Art. 5 detectors are opt-in; this means nothing was detected while they were enabled, not that no prohibited-practice request occurred.";

    /// <summary>The Art. 12 note shown when the period has no entries.</summary>
    internal const string Art12NoEntriesNote =
        "Entries are written by the sentinel-hook, sentinel-copilot-hook and sentinel-mcp tools, and by an in-process application that registers AI.Sentinel.Sqlite with this file. An application on the default in-memory audit store writes nothing here; check that --db names the file they write.";

    /// <summary>The Art. 14 note shown when nothing was recorded for human oversight.</summary>
    internal const string Art14NothingRecordedNote =
        "Authorization denials are recorded when a tool-call authorization policy refuses a call, and approval holds and decisions when an approval policy gates a tool. The hook tools and the MCP proxy write them to this file by default; an in-process application does only when it registers AI.Sentinel.Sqlite with this file.";

    /// <summary>The Art. 10 note shown when no redactions were recorded.</summary>
    internal const string Art10NoRedactionsNote =
        "Redaction entries come from the in-process chat client pipeline. The hook tools and the MCP proxy do not redact yet; a detection there that wanted redaction is counted as could not be redacted.";

    /// <summary>The Art. 50 note shown when no disclosures were recorded.</summary>
    internal const string Art50NoDisclosuresNote =
        "Transparency is opt-in through SentinelOptions.Transparency and applies to the in-process chat client only. The hook tools and the MCP proxy never write disclosures.";

    /// <summary>The Art. 15 note shown when no detections were recorded.</summary>
    internal const string Art15NoDetectionsNote =
        "A detection is recorded each time a detector fires on a scanned prompt, response or tool call. The semantic detectors only run with an embedding generator configured; without one only the rule-based detectors can fire.";

    /// <summary>The source label of entries written by an in-process application.</summary>
    internal const string InProcessSource = "in-process";

    /// <summary>Detections of one detector at one severity.</summary>
    /// <param name="DetectorId">The detector.</param>
    /// <param name="Severity">The severity.</param>
    /// <param name="Count">Number of entries.</param>
    internal sealed record DetectionCount(string DetectorId, Severity Severity, int Count);

    /// <summary>Detections of one detector at all severities.</summary>
    /// <param name="DetectorId">The detector.</param>
    /// <param name="Count">Number of entries.</param>
    internal sealed record DetectorTotal(string DetectorId, int Count);

    /// <summary>Record keeping and chain integrity.</summary>
    /// <param name="ChainIntact">True when the whole chain verified.</param>
    /// <param name="EntriesChecked">Entries verified before the first break, or in total when intact.</param>
    /// <param name="FirstBrokenEntryId">Id of the first entry that failed, or null.</param>
    /// <param name="HeadTrimmed">True when older entries were removed, for example by retention.</param>
    /// <param name="ChainNote">How the chain was verified.</param>
    /// <param name="EntriesInPeriod">Entries inside the period.</param>
    /// <param name="EntriesBySource">Entries per source; in-process applications show as in-process.</param>
    /// <param name="Note">What would put entries in the period; null when there are entries.</param>
    internal sealed record Art12Section(
        bool ChainIntact,
        long EntriesChecked,
        string? FirstBrokenEntryId,
        bool HeadTrimmed,
        string ChainNote,
        int EntriesInPeriod,
        IReadOnlyDictionary<string, int> EntriesBySource,
        string? Note);

    /// <summary>Human oversight.</summary>
    /// <param name="AuthorizationDenials">Number of AUTHZ-DENY entries, except approval holds.</param>
    /// <param name="ApprovalHolds">Number of AUTHZ-DENY entries with the approval-required code: a tool call held until a
    /// person approves it. A request held several times counts each time.</param>
    /// <param name="ApprovalRequestsByOutcome">Distinct approval requests per outcome.</param>
    /// <param name="Note">What would populate the section; null when anything was recorded.</param>
    internal sealed record Art14Section(
        int AuthorizationDenials,
        int ApprovalHolds,
        IReadOnlyDictionary<string, int> ApprovalRequestsByOutcome,
        string? Note);

    /// <summary>Data minimisation.</summary>
    /// <param name="RedactionsByType">Redacted occurrences per entity type.</param>
    /// <param name="FallbackEntries">Detections that wanted redaction and could not redact. These entries are also counted in Art15, or in Art5 for a CMP- detector.</param>
    /// <param name="Note">What would record redactions; null when there are redactions.</param>
    internal sealed record Art10Section(IReadOnlyDictionary<string, int> RedactionsByType, int FallbackEntries, string? Note);

    /// <summary>Transparency.</summary>
    /// <param name="DisclosedSessions">Distinct sessions with a disclosure entry.</param>
    /// <param name="Note">What would record disclosures; null when there are disclosures.</param>
    internal sealed record Art50Section(int DisclosedSessions, string? Note);

    /// <summary>Prohibited practices.</summary>
    /// <param name="AnyDetections">True when at least one CMP- detection was recorded.</param>
    /// <param name="Note">What an empty section does and does not mean; null when there are detections.</param>
    /// <param name="Detections">Detections per detector and severity.</param>
    internal sealed record Art5Section(bool AnyDetections, string? Note, IReadOnlyList<DetectionCount> Detections);

    /// <summary>Accuracy and robustness.</summary>
    /// <param name="Detections">Detections per detector and severity.</param>
    /// <param name="TopDetectors">The five detectors with the most detections.</param>
    /// <param name="Note">What would record detections; null when there are detections.</param>
    internal sealed record Art15Section(IReadOnlyList<DetectionCount> Detections, IReadOnlyList<DetectorTotal> TopDetectors, string? Note);
}
