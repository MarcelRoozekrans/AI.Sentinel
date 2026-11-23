namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>Where the forwarder reads the local audit from.</summary>
internal interface IAuditSource
{
    /// <summary>The entries with a sequence above <paramref name="after"/>, oldest first, at most <paramref name="limit"/>.</summary>
    Task<AuditPage> ReadAfterAsync(long after, int limit, CancellationToken ct);
}
