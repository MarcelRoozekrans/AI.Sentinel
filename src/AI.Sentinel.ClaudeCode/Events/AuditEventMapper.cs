using System.Globalization;
using AI.Sentinel.Audit;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>
/// Turns a local audit entry into the event the server takes (ADR-240). Only an entry the hook routed, with a tool kind, becomes
/// one: an entry of a call in strict repository mode, or of a PC with no server, has none and is never sent. What an event
/// holds is read from the entry's own fields; the command, paths and tool input are not in the audit, and so cannot be in an event.
/// </summary>
internal static class AuditEventMapper
{
    private const string FindingOutcome = "finding";
    private const string RedactedOutcome = "redacted";
    private const string AuthorizationDenyDetector = "AUTHZ-DENY";
    private const string ApprovalRequiredCode = "approval_required";

    /// <summary>The event of <paramref name="entry"/>, or <see langword="null"/> when it is not forwarded.</summary>
    /// <param name="entry">The audit entry.</param>
    /// <param name="detailedLogging">Whether the node of the entry turned on detailed logging; the reason is only sent then.</param>
    public static ForwardedEvent? Map(AuditEntry entry, Func<string?, bool> detailedLogging)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(detailedLogging);
        if (string.IsNullOrEmpty(entry.ToolKind))
        {
            return null;
        }

        var node = string.IsNullOrEmpty(entry.Node) ? null : entry.Node;
        var detailed = detailedLogging(node);
        if (string.Equals(entry.DetectorId, OutcomeAudit.DetectorId, StringComparison.Ordinal) && Outcome(entry.Summary) is { } parsed)
        {
            return Decision(entry, node, parsed, detailed);
        }

        if (string.Equals(entry.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal))
        {
            return Plain(entry, node, RedactedOutcome) with { Redactions = Counts(entry.Summary) };
        }

        if (string.Equals(entry.DetectorId, AuthorizationDenyDetector, StringComparison.Ordinal))
        {
            // The summary names the caller and the tool, so it is never sent; the code says whether this asked for an approval.
            var asked = string.Equals(entry.PolicyCode, ApprovalRequiredCode, StringComparison.Ordinal);
            return Plain(entry, node, asked ? "ask" : "deny");
        }

        return Plain(entry, node, FindingOutcome) with
        {
            Severity = entry.Severity.ToString().ToLowerInvariant(),
            Reason = detailed ? ReasonRedactor.Redact(entry.Summary) : null,
        };
    }

    private static ForwardedEvent Plain(AuditEntry entry, string? node, string outcome) => new()
    {
        EventId = Guid.TryParse(entry.Id, out var guid) ? guid.ToString("D", CultureInfo.InvariantCulture) : entry.Id,
        At = entry.Timestamp.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
        ToolKind = entry.ToolKind!,
        Outcome = outcome,
        Detector = entry.DetectorId,
        Node = node,
        Cli = entry.Source,
        Session = string.IsNullOrEmpty(entry.SessionId) ? null : entry.SessionId,
    };

    private static ForwardedEvent Decision(AuditEntry entry, string? node, ParsedOutcome o, bool detailed) =>
        Plain(entry, node, o.Name) with
        {
            Detector = null,
            Policies = o.Sources.Count == 0 ? null : o.Sources,
            PolicyVersion = NullIfEmpty(o.PolicyVersion),
            Decided = NullIfEmpty(o.Decided),
            Reason = detailed ? ReasonRedactor.Redact(o.Reason) : null,
        };

    private sealed record ParsedOutcome(string Name, string Reason, List<string> Sources, string PolicyVersion, string Decided);

    /// <summary>Reads <c>deny: reason; sources=a,b; policy=v1; decided=in-process</c>, see <see cref="OutcomeDecision.Summary"/>.</summary>
    private static ParsedOutcome? Outcome(string summary)
    {
        var colon = summary.IndexOf(": ", StringComparison.Ordinal);
        var sources = summary.LastIndexOf("; sources=", StringComparison.Ordinal);
        var policy = summary.LastIndexOf("; policy=", StringComparison.Ordinal);
        var decided = summary.LastIndexOf("; decided=", StringComparison.Ordinal);
        if (colon <= 0 || sources < colon || policy < sources || decided < policy)
        {
            return null;
        }

        var name = summary[..colon];
        var list = summary[(sources + "; sources=".Length)..policy]
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        return new ParsedOutcome(
            name, summary[(colon + 2)..sources], list,
            summary[(policy + "; policy=".Length)..decided], summary[(decided + "; decided=".Length)..]);
    }

    /// <summary>Reads <c>Redacted 1 EMAIL, 2 IBAN</c>, see <see cref="AuditEntryRedactionExtensions.Summarize"/>.</summary>
    private static Dictionary<string, int>? Counts(string summary)
    {
        const string prefix = "Redacted ";
        if (!summary.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var part in summary[prefix.Length..].Split(", ", StringSplitOptions.RemoveEmptyEntries))
        {
            var space = part.IndexOf(' ', StringComparison.Ordinal);
            if (space > 0 && int.TryParse(part[..space], NumberStyles.None, CultureInfo.InvariantCulture, out var n) && space + 1 < part.Length)
            {
                var kind = part[(space + 1)..];
                if (kind.Length <= 64 && counts.Count < 32)
                {
                    counts[kind] = counts.GetValueOrDefault(kind) + n;
                }
            }
        }

        return counts.Count == 0 ? null : counts;
    }

    private static string? NullIfEmpty(string value) => value.Length == 0 ? null : value;
}
