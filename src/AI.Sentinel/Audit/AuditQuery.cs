using AI.Sentinel.Detection;

namespace AI.Sentinel.Audit;

public sealed record AuditQuery(
    Severity? MinSeverity = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int PageSize = 200);
