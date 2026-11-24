using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

namespace AI.Sentinel.ClaudeCode;

/// <summary>The local audit entry of a decision that carries an <see cref="OutcomeDecision"/>: reason, sources, policy
/// version and where it was made. Informational, like a redaction, so it has no severity.</summary>
internal static class OutcomeAudit
{
    /// <summary><see cref="AuditEntry.DetectorId"/> of an outcome entry.</summary>
    public const string DetectorId = "OUTCOME";

    /// <summary><see cref="AuditEntry.PolicyCode"/> of an outcome entry.</summary>
    public const string PolicyCode = "OUTCOME";

    public static AuditEntry Entry(OutcomeDecision decision, string? sessionId)
    {
        ArgumentNullException.ThrowIfNull(decision);
        return new AuditEntry(
            Id: Guid.NewGuid().ToString("N"),
            Timestamp: DateTimeOffset.UtcNow,
            Hash: string.Empty,
            PreviousHash: null,
            Severity: Severity.None,
            DetectorId: DetectorId,
            Summary: decision.Summary())
        {
            PolicyCode = PolicyCode,
            SessionId = string.IsNullOrWhiteSpace(sessionId) ? null : sessionId,
        };
    }

    /// <summary>Records <paramref name="output"/>'s decision, when it has one; a legacy decision writes nothing.</summary>
    public static async Task RecordAsync(
        IAuditStore store, IReadOnlyList<IAuditForwarder> forwarders, HookOutput output, string? sessionId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(output);
        if (output.Outcome is null)
        {
            return;
        }

        await store.AppendAndForwardAsync(Entry(output.Outcome, sessionId), AuditForwarding.Snapshot(forwarders), ct).ConfigureAwait(false);
    }
}
