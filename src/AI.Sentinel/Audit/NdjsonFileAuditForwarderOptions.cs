namespace AI.Sentinel.Audit;

/// <summary>Configuration for <see cref="NdjsonFileAuditForwarder"/>.</summary>
public sealed class NdjsonFileAuditForwarderOptions
{
    /// <summary>Path to the NDJSON file. Appended to; created if missing.</summary>
    public string FilePath { get; set; } = "audit.ndjson";
}
