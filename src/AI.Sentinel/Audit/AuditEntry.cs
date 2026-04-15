using AI.Sentinel.Detection;

namespace AI.Sentinel;

// STUB — full implementation in Task 5
public sealed record AuditEntry(
    string Id,
    DateTimeOffset Timestamp,
    string Hash,
    string? PreviousHash,
    Severity Severity,
    string DetectorId,
    string Summary);
