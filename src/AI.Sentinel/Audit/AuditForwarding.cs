namespace AI.Sentinel.Audit;

/// <summary>
/// Appends an entry to the <see cref="IAuditStore"/> and mirrors the stored entry, with the chain
/// hashes the store assigned, to every <see cref="IAuditForwarder"/>. Shared by every surface that
/// writes audit entries so none of them forwards the unlinked entry or skips forwarding.
/// </summary>
internal static class AuditForwarding
{
    /// <summary>Copies <paramref name="source"/> once, so per-entry forwarding never re-enumerates DI.</summary>
    internal static IAuditForwarder[] Snapshot(IEnumerable<IAuditForwarder>? source)
    {
        if (source is null) return [];
        if (source is IAuditForwarder[] arr) return arr;
        return [.. source];
    }

    /// <summary>Appends <paramref name="entry"/>, forwards the stored entry and returns it.</summary>
    internal static async ValueTask<AuditEntry> AppendAndForwardAsync(
        this IAuditStore store,
        AuditEntry entry,
        IAuditForwarder[] forwarders,
        CancellationToken ct)
    {
        var stored = await store.AppendAsync(entry, ct).ConfigureAwait(false);
        Forward(stored, forwarders);
        return stored;
    }

    /// <summary>Fire-and-forget mirror of <paramref name="entry"/> to every forwarder.
    /// Each forwarder runs on its own <see cref="Task.Run(Func{Task})"/> continuation so a slow or buffered
    /// implementation cannot add latency to the caller. The caller's token is not passed on: the entry is
    /// already stored, and a request cancelled after that must not keep it from the forwarders.
    /// Exceptions are swallowed defensively even though forwarders MUST NOT throw.</summary>
    private static void Forward(AuditEntry entry, IAuditForwarder[] forwarders)
    {
        if (forwarders.Length == 0) return;
        foreach (var forwarder in forwarders)
        {
            var captured = forwarder;
            _ = Task.Run(async () =>
            {
#pragma warning disable ERP022 // fire-and-forget: forwarder failure must never surface to the caller
                try
                {
                    await captured.SendAsync(new[] { entry }, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    // IAuditForwarder MUST NOT throw, but defend in depth.
                }
#pragma warning restore ERP022
            });
        }
    }
}
