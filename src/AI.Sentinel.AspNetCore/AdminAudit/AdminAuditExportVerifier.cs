using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>Verifies an export offline: signed head against a pinned key, the chain, the head against the entries, then an optional checkpoint.</summary>
internal static class AdminAuditExportVerifier
{
    public static async ValueTask<AdminAuditVerification> VerifyAsync(
        ReadOnlyMemory<byte> utf8, PinnedProfileKeys pinned, string expectedOrganisation, AdminAuditCheckpoint? checkpoint, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(pinned);
        ArgumentException.ThrowIfNullOrEmpty(expectedOrganisation);

        AdminAuditExport? export;
        try
        {
            export = JsonSerializer.Deserialize(utf8.Span, AdminAuditJsonContext.Default.AdminAuditExport);
        }
        catch (JsonException)
        {
            return Reject(AdminAuditRejection.Malformed);
        }

        if (export?.Entries is not { } wire || export.Head is not { } head
            || head.Organisation is null || head.ExportedAt is null || head.Signature is null || head.KeyId is null
            || head.Count < 0 || !AdminAuditHead.TryParseTime(head.ExportedAt, out var exportedAt))
        {
            return Reject(AdminAuditRejection.Malformed);
        }

        var signed = new AdminAuditVerification(AdminAuditRejection.None, null, head.Count, exportedAt, head.LastHash);
        var headRejection = CheckHead(export, head, pinned, expectedOrganisation);
        if (headRejection != AdminAuditRejection.None)
        {
            return signed with { Rejection = headRejection };
        }

        var chain = new List<AuditEntry>(wire.Count);
        foreach (var w in wire)
        {
            if (!TryToChainEntry(w, expectedOrganisation, out var entry))
            {
                return signed with { Rejection = AdminAuditRejection.Malformed };
            }
            chain.Add(entry);
        }

        var rejection = await CheckEntriesAsync(chain, head, ct).ConfigureAwait(false);
        if (rejection.Rejection != AdminAuditRejection.None)
        {
            return signed with { Rejection = rejection.Rejection, FirstBrokenEntryId = rejection.FirstBrokenEntryId };
        }

        return checkpoint is not null && CheckCheckpoint(chain, head.Count, exportedAt, checkpoint) is var reason && reason != AdminAuditRejection.None
            ? signed with { Rejection = reason }
            : signed;
    }

    private static AdminAuditRejection CheckHead(AdminAuditExport export, AdminAuditHead head, PinnedProfileKeys pinned, string expectedOrganisation)
    {
        if (!string.Equals(export.Organisation, expectedOrganisation, StringComparison.Ordinal)
            || !string.Equals(head.Organisation, expectedOrganisation, StringComparison.Ordinal))
        {
            return AdminAuditRejection.WrongOrganisation;
        }
        if (!pinned.TryGet(head.KeyId!, out var publicKey))
        {
            return AdminAuditRejection.UnknownKey;
        }
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(head.Signature!);
        }
        catch (FormatException)
        {
            return AdminAuditRejection.BadSignature;
        }
        var message = AdminAuditHead.SigningBytes(head.Organisation!, head.Count, head.LastHash, head.ExportedAt!);
        return Ed25519Crypto.Verify(publicKey, message, signature) ? AdminAuditRejection.None : AdminAuditRejection.BadSignature;
    }

    private static async ValueTask<AdminAuditVerification> CheckEntriesAsync(List<AuditEntry> chain, AdminAuditHead head, CancellationToken ct)
    {
        var verification = await AuditHashChain.VerifyAsync(ToAsync(chain), ct).ConfigureAwait(false);
        if (!verification.IsIntact)
        {
            return Reject(AdminAuditRejection.ChainBroken) with { FirstBrokenEntryId = verification.FirstBrokenEntryId };
        }
        if (verification.AnchorHash is not null)
        {
            return Reject(AdminAuditRejection.StartMissing) with { FirstBrokenEntryId = chain[0].Id };
        }
        var last = chain.Count == 0 ? null : chain[^1].Hash;
        return chain.Count != head.Count || !string.Equals(last, head.LastHash, StringComparison.Ordinal)
            ? Reject(AdminAuditRejection.HeadMismatch)
            : Reject(AdminAuditRejection.None);
    }

    private static AdminAuditRejection CheckCheckpoint(
        List<AuditEntry> chain, long count, DateTimeOffset exportedAt, AdminAuditCheckpoint checkpoint)
    {
        if (count < checkpoint.Count || exportedAt < checkpoint.ExportedAt)
        {
            return AdminAuditRejection.OlderThanCheckpoint;
        }
        return checkpoint.Count < 1 || checkpoint.Count > chain.Count
            || !string.Equals(chain[(int)checkpoint.Count - 1].Hash, checkpoint.Hash, StringComparison.Ordinal)
            ? AdminAuditRejection.CheckpointNotContained
            : AdminAuditRejection.None;
    }

    private static AdminAuditVerification Reject(AdminAuditRejection reason) => new(reason, null, 0, null, null);

    private static bool TryToChainEntry(AdminAuditEntryWire w, string organisation, out AuditEntry entry)
    {
        entry = null!;
        if (w.Id is null || w.Hash is null || w.Action is null || w.Actor is null || w.Target is null || w.Channel is null
            || !string.Equals(w.Organisation, organisation, StringComparison.Ordinal)
            || !AdminAuditHead.TryParseTime(w.Timestamp, out var at)
            || !AdminAuditNames.IsKnownAction(w.Action) || !AdminAuditNames.IsKnownChannel(w.Channel))
        {
            return false;
        }
        entry = new AdminAuditEntry(w.Id, at, organisation, w.Action, w.Actor, w.Target, w.Channel, w.PreviousHash, w.Hash).ToChainEntry();
        return true;
    }

    private static async IAsyncEnumerable<AuditEntry> ToAsync(List<AuditEntry> entries)
    {
        foreach (var e in entries)
        {
            yield return e;
        }
        await Task.CompletedTask.ConfigureAwait(false);
    }
}
