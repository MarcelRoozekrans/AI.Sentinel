using AI.Sentinel.Audit;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>The in-memory <see cref="IAdminAuditStore"/>. Entries live as long as the process; a persistent store is a separate piece of work.</summary>
internal sealed class InMemoryAdminAuditStore : IAdminAuditStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, List<AdminAuditEntry>> _byOrganisation = new(StringComparer.Ordinal);

    public ValueTask<AdminAuditEntry> AppendAsync(
        string organisation, AdminAuditAction action, string actor, string target, AdminAuditChannel channel,
        DateTimeOffset at, CancellationToken ct)
    {
        AdminAuditEntry.CheckField(organisation, nameof(organisation));
        AdminAuditEntry.CheckField(actor, nameof(actor));
        AdminAuditEntry.CheckField(target, nameof(target));
        ct.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (!_byOrganisation.TryGetValue(organisation, out var list))
            {
                list = [];
                _byOrganisation[organisation] = list;
            }

            var draft = new AdminAuditEntry(
                Guid.NewGuid().ToString("N"), at.ToUniversalTime(), organisation, AdminAuditNames.Of(action),
                actor, target, AdminAuditNames.Of(channel), null, string.Empty);
            var linked = AuditHashChain.Link(draft.ToChainEntry(), list.Count == 0 ? null : list[^1].Hash);
            var entry = AdminAuditEntry.FromChainEntry(linked);
            list.Add(entry);
            return ValueTask.FromResult(entry);
        }
    }

    public ValueTask<IReadOnlyList<AdminAuditEntry>> ReadAsync(string organisation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(organisation);
        lock (_gate)
        {
            IReadOnlyList<AdminAuditEntry> copy = _byOrganisation.TryGetValue(organisation, out var list) ? [.. list] : [];
            return ValueTask.FromResult(copy);
        }
    }

    public ValueTask UpdateAsync(string id, CancellationToken ct) =>
        throw new AdminAuditAppendOnlyException("The administrative audit log is append-only: an entry cannot be updated.");

    public ValueTask DeleteAsync(string id, CancellationToken ct) =>
        throw new AdminAuditAppendOnlyException("The administrative audit log is append-only: an entry cannot be deleted.");
}
