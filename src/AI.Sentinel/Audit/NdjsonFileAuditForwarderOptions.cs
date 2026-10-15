namespace AI.Sentinel.Audit;

/// <summary>Configuration for <see cref="NdjsonFileAuditForwarder"/>.</summary>
public sealed class NdjsonFileAuditForwarderOptions
{
    /// <summary>Path to the NDJSON file. Appended to; created if missing.</summary>
    public string FilePath { get; set; } = "audit.ndjson";

    /// <summary>
    /// Receives each send failure or dropped batch as a one-line message. When null, the message
    /// is written to <see cref="Console.Error"/>. Set it when stderr is reserved for other output,
    /// as in a hook process. The callback must not throw; an exception from it is ignored.
    /// </summary>
    public Action<string>? OnError { get; set; }
}
