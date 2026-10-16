using System.Globalization;
using System.Text;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Audit;

/// <summary>Factory helpers on <see cref="AuditEntry"/> for redactions.</summary>
public static class AuditEntryRedactionExtensions
{
    /// <summary><see cref="AuditEntry.PolicyCode"/> of a redaction entry.</summary>
    public const string RedactedPolicyCode = "REDACTED";

    /// <summary>
    /// Builds the audit entry for the values one redacting detector replaced in one call. A redaction is
    /// compliance evidence, not a threat: the entry has <see cref="Severity.None"/> and
    /// <see cref="RedactedPolicyCode"/>, and its summary carries counts per entity type only, for example
    /// <c>Redacted 1 EMAIL, 1 IBAN</c>, with the types in ordinal order. It never carries a value.
    /// </summary>
    /// <param name="detectorId">Id of the detector that found the values.</param>
    /// <param name="counts">Number of redacted occurrences per entity type.</param>
    /// <param name="sessionId">Session of the call.</param>
    public static AuditEntry Redaction(string detectorId, IReadOnlyDictionary<string, int> counts, string sessionId)
    {
        ArgumentNullException.ThrowIfNull(detectorId);
        ArgumentNullException.ThrowIfNull(counts);
        ArgumentNullException.ThrowIfNull(sessionId);

        return new AuditEntry(
            Id: Guid.NewGuid().ToString("N"),
            Timestamp: DateTimeOffset.UtcNow,
            Hash: string.Empty,
            PreviousHash: null,
            Severity: Severity.None,
            DetectorId: detectorId,
            Summary: Summarize(counts))
        {
            PolicyCode = RedactedPolicyCode,
            SessionId = sessionId,
        };
    }

    /// <summary><c>Redacted 1 EMAIL, 1 IBAN</c>: counts per type, types in ordinal order.</summary>
    internal static string Summarize(IReadOnlyDictionary<string, int> counts)
    {
        var types = new List<string>(counts.Keys);
        types.Sort(StringComparer.Ordinal);
        var sb = new StringBuilder("Redacted ");
        for (var i = 0; i < types.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(", ");
            }
            sb.Append(counts[types[i]].ToString(CultureInfo.InvariantCulture)).Append(' ').Append(types[i]);
        }
        return sb.ToString();
    }
}
