namespace AI.Sentinel.Approvals.Configuration;

/// <summary>The approval-store backend selected by an <see cref="ApprovalConfig"/>. CLIs
/// dispatch to the appropriate <c>AddSentinel*ApprovalStore</c> extension based on this.</summary>
public enum ApprovalBackendKind
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
}
