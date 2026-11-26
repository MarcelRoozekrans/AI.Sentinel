using System.Text.Json;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>Records administrative actions and exports one organisation's log with a head signed by the deployment key.</summary>
internal sealed class AdminAuditLog(IAdminAuditStore store, ProfileSigningKeys keys, TimeProvider time)
{
    /// <summary>Appends an entry for <paramref name="action"/>.</summary>
    public ValueTask<AdminAuditEntry> RecordAsync(
        string organisation, AdminAuditAction action, string actor, string target, AdminAuditChannel channel, CancellationToken ct) =>
        store.AppendAsync(organisation, action, actor, target, channel, time.GetUtcNow(), ct);

    /// <summary>The export as UTF-8 JSON: entries oldest first, then the signed head.</summary>
    public async ValueTask<byte[]> ExportAsync(string organisation, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(organisation);
        var entries = await store.ReadAsync(organisation, ct).ConfigureAwait(false);
        var exportedAt = AdminAuditHead.FormatTime(time.GetUtcNow());
        var lastHash = entries.Count == 0 ? null : entries[^1].Hash;
        var signature = keys.Current.Sign(AdminAuditHead.SigningBytes(organisation, entries.Count, lastHash, exportedAt));

        var export = new AdminAuditExport
        {
            Organisation = organisation,
            Entries = [.. entries.Select(e => new AdminAuditEntryWire
            {
                Id = e.Id,
                Timestamp = AdminAuditHead.FormatTime(e.Timestamp),
                Organisation = e.Organisation,
                Action = e.Action,
                Actor = e.Actor,
                Target = e.Target,
                Channel = e.Channel,
                PreviousHash = e.PreviousHash,
                Hash = e.Hash,
            })],
            Head = new AdminAuditHead
            {
                Organisation = organisation,
                Count = entries.Count,
                LastHash = lastHash,
                ExportedAt = exportedAt,
                KeyId = keys.Current.KeyId,
                Signature = Convert.ToBase64String(signature),
            },
        };
        return JsonSerializer.SerializeToUtf8Bytes(export, AdminAuditJsonContext.Default.AdminAuditExport);
    }
}
