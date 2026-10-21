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

    /// <summary>
    /// How long a send waits for the lock file (<c>&lt;FilePath&gt;.lock</c>) that serialises appends from several
    /// forwarders and processes to one file. A batch that cannot take the lock in time is dropped and reported
    /// through <see cref="OnError"/> like any other send failure. Must be positive. Default 5 seconds.
    /// </summary>
    public TimeSpan LockTimeout { get; set; } = TimeSpan.FromSeconds(5);
}
