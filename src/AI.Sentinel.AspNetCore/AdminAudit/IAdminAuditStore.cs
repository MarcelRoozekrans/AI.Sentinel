using AI.Sentinel.Audit;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>
/// Append-only store of administrative actions, hash-chained per organisation. It refuses updates and deletes.
/// </summary>
internal interface IAdminAuditStore
{
    /// <summary>Appends an entry, chained after the last entry of <paramref name="organisation"/>.</summary>
    ValueTask<AdminAuditEntry> AppendAsync(
        string organisation, AdminAuditAction action, string actor, string target, AdminAuditChannel channel,
        DateTimeOffset at, CancellationToken ct);

    /// <summary>Every entry of one organisation, oldest first.</summary>
    ValueTask<IReadOnlyList<AdminAuditEntry>> ReadAsync(string organisation, CancellationToken ct);

    /// <summary>Always refused: the log is append-only.</summary>
    ValueTask UpdateAsync(string id, CancellationToken ct);

    /// <summary>Always refused: the log is append-only.</summary>
    ValueTask DeleteAsync(string id, CancellationToken ct);
}
