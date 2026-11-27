namespace AI.Sentinel.Approvals.Configuration;

/// <summary>The approval-store backend selected by an <see cref="ApprovalConfig"/>. CLIs
/// dispatch to the appropriate <c>AddSentinel*ApprovalStore</c> extension based on this.</summary>
internal enum ApprovalBackendKind
{
    /// <summary>No approval store (config.Backend = "none"). Bindings with ApprovalSpec
    /// will throw at first authorize call — useful for dry-run / linting scenarios.</summary>
    None,

    /// <summary>In-memory store (process-local, lost on restart). Backend = "in-memory".</summary>
    InMemory,

    /// <summary>SQLite store. Backend = "sqlite". Requires <see cref="ApprovalConfig.DatabasePath"/>.</summary>
    Sqlite,

    /// <summary>Entra PIM store. Backend = "entra-pim". Requires <see cref="ApprovalConfig.TenantId"/>.</summary>
    EntraPim,

    /// <summary>The approval server (#662). Backend = "http". Only <c>sentinel-hook</c> serves it, through the resident process;
    /// the server address and the sign-in are the hook's <c>SENTINEL_HOOK_</c> settings, so the file names nothing else.</summary>
    Http,
}
