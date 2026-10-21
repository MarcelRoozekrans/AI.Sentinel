using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Wraps approval stores so that their decisions reach the audit log, and builds the informational entry each
/// decision writes. A store registered through
/// <see cref="ApprovalStoreServiceCollectionExtensions.AddSentinelApprovalStore{TStore}"/> is wrapped once by DI; every
/// consumer of the store, in AI.Sentinel and in the host, then gets the same wrapper, so a decision is recorded
/// exactly once wherever it is made.
/// </summary>
internal static class ApprovalStoreAuditing
{
    /// <summary>The service key of the inner store, which only the wrapper resolves.</summary>
    internal static readonly object InnerStoreKey = new();

    /// <summary>
    /// What this process has seen of each inner store's requests. It is kept per inner store, not per wrapper, because
    /// a store registered straight as <see cref="IApprovalStore"/> gets a wrapper per <see cref="Resolve"/> call: the
    /// guard sees the request open, the chat client sees it settle.
    /// </summary>
    private static readonly ConditionalWeakTable<IApprovalStore, ApprovalAuditMemory> Memories = new();

    /// <summary>
    /// Returns the registered <see cref="IApprovalStore"/> wrapped by <see cref="AuditingApprovalStore"/> when an
    /// <see cref="IAuditStore"/> is registered, the store itself when none is, and <see langword="null"/> when no store
    /// is registered. A store registered through <see cref="ApprovalStoreServiceCollectionExtensions.AddSentinelApprovalStore{TStore}"/> is returned as DI hands it out,
    /// already wrapped; one registered straight as <see cref="IApprovalStore"/> is wrapped here. The wrapper implements
    /// <see cref="IApprovalAdmin"/> exactly when the store does.
    /// </summary>
    /// <param name="sp">The provider to resolve the store, the audit store and the forwarders from.</param>
    internal static IApprovalStore? Resolve(IServiceProvider sp)
    {
        ArgumentNullException.ThrowIfNull(sp);
        var store = sp.GetService<IApprovalStore>();
        return store is null or AuditingApprovalStore ? store : Wrap(sp, store);
    }

    /// <summary>
    /// Wraps <paramref name="inner"/> when an <see cref="IAuditStore"/> is registered, and returns it unwrapped when
    /// none is. Every wrapper over the same inner store shares one <see cref="ApprovalAuditMemory"/>.
    /// </summary>
    internal static IApprovalStore Wrap(IServiceProvider sp, IApprovalStore inner)
    {
        var audit = sp.GetService<IAuditStore>();
        if (audit is null)
        {
            return inner;
        }

        var forwarders = AuditForwarding.Snapshot(sp.GetServices<IAuditForwarder>());
        var logger = sp.GetService<ILogger<AuditingApprovalStore>>();
        var memory = Memories.GetValue(inner, static _ => new ApprovalAuditMemory());
        return inner is IApprovalAdmin admin
            ? new AuditingApprovalAdminStore(inner, admin, audit, forwarders, logger, memory)
            : new AuditingApprovalStore(inner, audit, forwarders, logger, memory);
    }

    /// <summary>
    /// The request id the summary of an approval decision entry names, read after the last
    /// <see cref="AuditEntryKinds.ApprovalRequestMarker"/>, or an empty string when it names none.
    /// </summary>
    /// <param name="summary">The summary <see cref="Decision"/> built.</param>
    internal static string RequestIdOf(string summary)
    {
        ArgumentNullException.ThrowIfNull(summary);
        var at = summary.LastIndexOf(AuditEntryKinds.ApprovalRequestMarker, StringComparison.Ordinal);
        return at < 0 ? string.Empty : summary[(at + AuditEntryKinds.ApprovalRequestMarker.Length)..].Trim();
    }

    /// <summary>The store DI hands out for a store registered through <see cref="ApprovalStoreServiceCollectionExtensions.AddSentinelApprovalStore{TStore}"/>.</summary>
    internal sealed class RegisteredApprovalStore(IApprovalStore store)
    {
        public IApprovalStore Store { get; } = store;
    }

    /// <summary>
    /// Builds the informational audit entry of one approval decision: <see cref="Severity.None"/>, the
    /// <see cref="AuditEntryKinds.ApprovalDetectorId"/> detector id and <paramref name="policyCode"/>. The summary reads
    /// <c>Approved: policy p, tool t, request r</c> and never carries the arguments, a note, a reason or an identity.
    /// </summary>
    /// <param name="policyCode">One of the four approval policy codes in <see cref="AuditEntryKinds"/>.</param>
    /// <param name="policyName">The approval policy.</param>
    /// <param name="toolName">The gated tool.</param>
    /// <param name="requestId">The approval request.</param>
    internal static AuditEntry Decision(string policyCode, string policyName, string toolName, string requestId)
    {
        ArgumentNullException.ThrowIfNull(policyCode);
        ArgumentNullException.ThrowIfNull(policyName);
        ArgumentNullException.ThrowIfNull(toolName);
        ArgumentNullException.ThrowIfNull(requestId);

        var outcome = policyCode switch
        {
            AuditEntryKinds.ApprovedPolicyCode => "Approved",
            AuditEntryKinds.DeniedPolicyCode => "Denied",
            AuditEntryKinds.ExpiredPolicyCode => "Expired",
            AuditEntryKinds.TimedOutPolicyCode => "Timed out",
            _ => throw new ArgumentOutOfRangeException(nameof(policyCode), policyCode, "Not an approval policy code."),
        };

        return new AuditEntry(
            Id: Guid.NewGuid().ToString("N"),
            Timestamp: DateTimeOffset.UtcNow,
            Hash: string.Empty,
            PreviousHash: null,
            Severity: Severity.None,
            DetectorId: AuditEntryKinds.ApprovalDetectorId,
            Summary: $"{outcome}: policy {policyName}, tool {toolName}{AuditEntryKinds.ApprovalRequestMarker}{requestId}")
        {
            PolicyCode = policyCode,
        };
    }
}
