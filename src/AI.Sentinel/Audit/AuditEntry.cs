using AI.Sentinel.Detection;

namespace AI.Sentinel.Audit;

/// <summary>
/// One record in an <see cref="IAuditStore"/>. The seven constructor parameters are required; the
/// optional fields are init properties, so new ones can be added without breaking callers.
/// </summary>
/// <param name="Id">Unique entry ID.</param>
/// <param name="Timestamp">When the entry was recorded.</param>
/// <param name="Hash">Set by the store; see <see cref="AuditHashChain"/>.</param>
/// <param name="PreviousHash">Set by the store: the previous entry's hash, or <see langword="null"/> for the first entry.</param>
/// <param name="Severity">Severity of the detection.</param>
/// <param name="DetectorId">ID of the detector or subsystem that wrote the entry.</param>
/// <param name="Summary">Human-readable summary.</param>
public sealed record AuditEntry(
    string Id,
    DateTimeOffset Timestamp,
    string Hash,
    string? PreviousHash,
    Severity Severity,
    string DetectorId,
    string Summary)
{
    /// <summary>The authorization policy code, set on AUTHZ-DENY entries only.</summary>
    public string? PolicyCode { get; init; }

    /// <summary>The session the entry was recorded for.</summary>
    public string? SessionId { get; init; }

    /// <summary>The tool that wrote the entry, one of <see cref="AuditSources"/>; <see langword="null"/> for in-process apps.</summary>
    public string? Source { get; init; }
}
