using AI.Sentinel.Detection;

namespace AI.Sentinel.Audit;

/// <summary>
/// Names the kinds of informational audit entries: evidence that something happened, not a detection.
/// Redactions, disclosures and approval decisions all have <see cref="Severity.None"/> and a
/// <see cref="AuditEntry.PolicyCode"/>, and consumers treat them as one concept.
/// </summary>
public static class AuditEntryKinds
{
    /// <summary><see cref="AuditEntry.PolicyCode"/> of an AI-disclosure entry.</summary>
    public const string DisclosedPolicyCode = "DISCLOSED";

    /// <summary><see cref="AuditEntry.PolicyCode"/> of an approved approval decision.</summary>
    public const string ApprovedPolicyCode = "APPROVED";

    /// <summary><see cref="AuditEntry.PolicyCode"/> of a denied approval decision.</summary>
    public const string DeniedPolicyCode = "DENIED";

    /// <summary><see cref="AuditEntry.PolicyCode"/> of an expired approval decision.</summary>
    public const string ExpiredPolicyCode = "EXPIRED";

    /// <summary><see cref="AuditEntry.PolicyCode"/> of a timed-out approval decision.</summary>
    public const string TimedOutPolicyCode = "TIMED_OUT";

    /// <summary><see cref="AuditEntry.DetectorId"/> of disclosure entries.</summary>
    public const string TransparencyDetectorId = "TRANSPARENCY";

    /// <summary><see cref="AuditEntry.DetectorId"/> of approval decision entries.</summary>
    public const string ApprovalDetectorId = "APPROVAL";

    /// <summary>
    /// Separates the request id, which ends an approval decision's summary, from the rest. The writer and the
    /// compliance report's parser share it, so the two cannot drift apart.
    /// </summary>
    internal const string ApprovalRequestMarker = ", request ";

    /// <summary>
    /// True for an informational entry: <see cref="Severity.None"/> with a <see cref="AuditEntry.PolicyCode"/>.
    /// A detection, including an authorization denial, has a real severity and is not informational.
    /// </summary>
    /// <param name="entry">The entry to classify.</param>
    public static bool IsInformational(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return entry.Severity == Severity.None && entry.PolicyCode is not null;
    }

    internal static bool IsRedaction(AuditEntry entry) =>
        IsInformational(entry)
        && string.Equals(entry.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal);

    internal static bool IsDisclosure(AuditEntry entry) =>
        IsInformational(entry)
        && string.Equals(entry.PolicyCode, DisclosedPolicyCode, StringComparison.Ordinal);

    internal static bool IsApproval(AuditEntry entry) =>
        IsInformational(entry)
        && entry.PolicyCode is ApprovedPolicyCode or DeniedPolicyCode or ExpiredPolicyCode or TimedOutPolicyCode;
}
