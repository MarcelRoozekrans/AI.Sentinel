using ZeroAlloc.Telemetry;

namespace AI.Sentinel.Audit;

/// <summary>Ships audit entries to an external system (SIEM, log aggregator, etc.). Implementations MUST NOT throw — failures are swallowed and surfaced via stderr / metrics.</summary>
[Instrument("ai.sentinel")]
public interface IAuditForwarder
{
    /// <summary>Sends a batch of audit entries. Single-entry lists are valid for forwarders without buffering.</summary>
    [Trace("audit.forward.send")]
    [Count("audit.forward.batches")]
    [Histogram("audit.forward.duration_ms")]
    ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct);
}
