using System.Globalization;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli.Report;

/// <summary>Builds a <see cref="ComplianceReport"/> from an audit store. Read-only: it only queries.</summary>
internal static class ComplianceReportBuilder
{
    private const string Art5Prefix = "CMP-";
    private const string RedactedPrefix = "Redacted ";
    private const string NotRedactedSuffix = "; not redacted";
    private const string UnknownRequest = "unknown";
    private const int TopDetectorCount = 5;

    /// <summary>
    /// Verifies the chain over the whole store, then counts the entries of the period. Totals only: no summary text,
    /// session id or caller id reaches the report.
    /// </summary>
    /// <param name="store">The audit store to read.</param>
    /// <param name="from">Start of the period.</param>
    /// <param name="to">End of the period.</param>
    /// <param name="auditFilePath">The audit file, shown in the header.</param>
    /// <param name="time">Clock for the generation time.</param>
    /// <param name="ct">Cancellation token.</param>
    internal static async ValueTask<ComplianceReport> BuildAsync(
        IAuditStore store, DateTimeOffset from, DateTimeOffset to, string auditFilePath, TimeProvider time, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(auditFilePath);
        ArgumentNullException.ThrowIfNull(time);

        var chain = await AuditHashChain.VerifyAsync(
            store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, ct), ct).ConfigureAwait(false);

        var tally = new Tally();
        var period = new AuditQuery { From = from, To = to, PageSize = int.MaxValue };
        await foreach (var entry in store.QueryAsync(period, ct).WithCancellation(ct).ConfigureAwait(false))
        {
            tally.Add(entry);
        }

        var approvals = tally.ApprovalCounts();
        var art15 = Detections(tally.Art15);
        return new ComplianceReport(
            Schema: 1,
            From: from,
            To: to,
            GeneratedAt: time.GetUtcNow(),
            AuditFilePath: auditFilePath,
            Disclaimer: ComplianceReport.DisclaimerText,
            Art12: new ComplianceReport.Art12Section(
                chain.IsIntact,
                chain.EntriesChecked,
                chain.FirstBrokenEntryId,
                chain.AnchorHash is not null,
                ComplianceReport.ChainNote,
                tally.EntriesInPeriod,
                Sorted(tally.BySource),
                NoteWhen(tally.EntriesInPeriod == 0, ComplianceReport.Art12NoEntriesNote)),
            Art14: new ComplianceReport.Art14Section(
                tally.Denials,
                tally.Holds,
                approvals,
                NoteWhen(tally.Denials == 0 && tally.Holds == 0 && approvals.Count == 0, ComplianceReport.Art14NothingRecordedNote)),
            Art10: new ComplianceReport.Art10Section(
                Sorted(tally.Redactions),
                tally.Fallbacks,
                NoteWhen(tally.Redactions.Count == 0, ComplianceReport.Art10NoRedactionsNote)),
            Art50: new ComplianceReport.Art50Section(
                tally.DisclosedTotal,
                NoteWhen(tally.DisclosedTotal == 0, ComplianceReport.Art50NoDisclosuresNote)),
            Art5: new ComplianceReport.Art5Section(
                tally.Art5.Count > 0, NoteWhen(tally.Art5.Count == 0, ComplianceReport.Art5NoDetectionsNote), Detections(tally.Art5)),
            Art15: new ComplianceReport.Art15Section(
                art15,
                TopDetectors(tally.Art15),
                NoteWhen(art15.Count == 0, ComplianceReport.Art15NoDetectionsNote)));
    }

    /// <summary>The note that says why a section is empty, or null when it is not.</summary>
    private static string? NoteWhen(bool empty, string note) => empty ? note : null;

    private static Dictionary<string, int> Sorted(Dictionary<string, int> source)
    {
        var keys = new List<string>(source.Keys);
        keys.Sort(StringComparer.Ordinal);
        var result = new Dictionary<string, int>(keys.Count, StringComparer.Ordinal);
        foreach (var key in keys)
        {
            result[key] = source[key];
        }
        return result;
    }

    private static List<ComplianceReport.DetectionCount> Detections(Dictionary<(string Detector, Severity Severity), int> counts)
    {
        var list = new List<ComplianceReport.DetectionCount>(counts.Count);
        foreach (var ((detector, severity), count) in counts)
        {
            list.Add(new ComplianceReport.DetectionCount(detector, severity, count));
        }
        list.Sort(static (a, b) =>
        {
            var byDetector = string.CompareOrdinal(a.DetectorId, b.DetectorId);
            return byDetector != 0 ? byDetector : a.Severity.CompareTo(b.Severity);
        });
        return list;
    }

    private static List<ComplianceReport.DetectorTotal> TopDetectors(Dictionary<(string Detector, Severity Severity), int> counts)
    {
        var totals = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var ((detector, _), count) in counts)
        {
            totals[detector] = totals.GetValueOrDefault(detector) + count;
        }
        var list = new List<ComplianceReport.DetectorTotal>(totals.Count);
        foreach (var (detector, count) in totals)
        {
            list.Add(new ComplianceReport.DetectorTotal(detector, count));
        }
        list.Sort(static (a, b) =>
        {
            var byCount = b.Count.CompareTo(a.Count);
            return byCount != 0 ? byCount : string.CompareOrdinal(a.DetectorId, b.DetectorId);
        });
        return list.Count > TopDetectorCount ? list.GetRange(0, TopDetectorCount) : list;
    }

    /// <summary>Running counts. Request and session ids live here only while counting; the model never gets them.</summary>
    private sealed class Tally
    {
        private readonly Dictionary<string, HashSet<string>> _approvalIds = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _unknownApprovals = new(StringComparer.Ordinal);

        internal int EntriesInPeriod { get; private set; }
        internal int Denials { get; private set; }
        internal int Holds { get; private set; }
        internal int Fallbacks { get; private set; }
        internal Dictionary<string, int> BySource { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, int> Redactions { get; } = new(StringComparer.Ordinal);
        internal HashSet<string> DisclosedSessions { get; } = new(StringComparer.Ordinal);
        internal int AnonymousDisclosures { get; private set; }
        internal int DisclosedTotal => DisclosedSessions.Count + AnonymousDisclosures;
        internal Dictionary<(string Detector, Severity Severity), int> Art5 { get; } = [];
        internal Dictionary<(string Detector, Severity Severity), int> Art15 { get; } = [];

        internal void Add(AuditEntry entry)
        {
            EntriesInPeriod++;
            var source = entry.Source ?? ComplianceReport.InProcessSource;
            BySource[source] = BySource.GetValueOrDefault(source) + 1;

            if (string.Equals(entry.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal))
            {
                // An approval hold is written as a denial with its own code; it is oversight working, not a refusal.
                if (string.Equals(entry.PolicyCode, SentinelDenyCodes.ApprovalRequired, StringComparison.Ordinal))
                {
                    Holds++;
                }
                else
                {
                    Denials++;
                }
            }
            else if (AuditEntryKinds.IsRedaction(entry))
            {
                CountRedactions(entry.Summary);
            }
            else if (AuditEntryKinds.IsDisclosure(entry))
            {
                // A disclosure without a session cannot be told apart from another, so each one counts as its own.
                if (entry.SessionId is null)
                {
                    AnonymousDisclosures++;
                }
                else
                {
                    DisclosedSessions.Add(entry.SessionId);
                }
            }
            else if (AuditEntryKinds.IsApproval(entry))
            {
                CountApproval(entry);
            }
            else if (AuditEntryKinds.IsInformational(entry))
            {
                // A future informational kind: evidence, not a detection.
            }
            else
            {
                CountDetection(entry);
            }
        }

        internal Dictionary<string, int> ApprovalCounts()
        {
            var outcomes = new SortedSet<string>(_approvalIds.Keys, StringComparer.Ordinal);
            outcomes.UnionWith(_unknownApprovals.Keys);
            var result = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var outcome in outcomes)
            {
                var distinct = _approvalIds.TryGetValue(outcome, out var ids) ? ids.Count : 0;
                result[outcome] = distinct + _unknownApprovals.GetValueOrDefault(outcome);
            }
            return result;
        }

        private void CountDetection(AuditEntry entry)
        {
            if (entry.Summary.EndsWith(NotRedactedSuffix, StringComparison.Ordinal))
            {
                Fallbacks++;
            }

            var target = entry.DetectorId.StartsWith(Art5Prefix, StringComparison.Ordinal) ? Art5 : Art15;
            var key = (entry.DetectorId, entry.Severity);
            target[key] = target.GetValueOrDefault(key) + 1;
        }

        private void CountApproval(AuditEntry entry)
        {
            var outcome = entry.PolicyCode!;
            var id = ApprovalStoreAuditing.RequestIdOf(entry.Summary);
            if (id.Length == 0 || string.Equals(id, UnknownRequest, StringComparison.Ordinal))
            {
                _unknownApprovals[outcome] = _unknownApprovals.GetValueOrDefault(outcome) + 1;
                return;
            }

            if (!_approvalIds.TryGetValue(outcome, out var ids))
            {
                ids = new HashSet<string>(StringComparer.Ordinal);
                _approvalIds[outcome] = ids;
            }
            ids.Add(id);
        }

        /// <summary>Parses <c>Redacted 1 EMAIL, 1 IBAN</c>; a part that does not read as count and type is skipped.</summary>
        private void CountRedactions(string summary)
        {
            if (!summary.StartsWith(RedactedPrefix, StringComparison.Ordinal))
            {
                return;
            }

            foreach (var part in summary[RedactedPrefix.Length..].Split(", "))
            {
                var space = part.IndexOf(' ', StringComparison.Ordinal);
                if (space <= 0 || space == part.Length - 1
                    || !int.TryParse(part.AsSpan(0, space), NumberStyles.None, CultureInfo.InvariantCulture, out var count))
                {
                    continue;
                }

                var type = part[(space + 1)..];
                Redactions[type] = Redactions.GetValueOrDefault(type) + count;
            }
        }
    }
}
