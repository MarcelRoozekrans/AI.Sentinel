using AI.Sentinel.Audit;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>Thrown when something tries to change or remove an entry of the append-only log.</summary>
internal sealed class AdminAuditAppendOnlyException(string message) : InvalidOperationException(message);
