using AI.Sentinel.Detection;

namespace AI.Sentinel.Audit;

public sealed record AuditEntry(
    string Id,
    DateTimeOffset Timestamp,
    string Hash,
    string? PreviousHash,
    Severity Severity,
    string DetectorId,
    string Summary);
