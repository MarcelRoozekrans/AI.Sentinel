using System;
using System.Collections.Generic;
using System.Globalization;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Audit;

/// <summary>Factory helpers on <see cref="AuditEntry"/> for tool-call authorization denials.</summary>
public static class AuditEntryAuthorizationExtensions
{
    /// <summary>Detector identifier emitted for tool-call authorization denials.</summary>
    public const string AuthorizationDenyDetectorId = "AUTHZ-DENY";

    /// <summary>
    /// Builds an <see cref="AuditEntry"/> describing a tool-call authorization denial.
    /// The entry has <c>DetectorId = "AUTHZ-DENY"</c> and <see cref="Severity.High"/>; the
    /// caller, roles, tool, policy, code and reason are encoded into <see cref="AuditEntry.Summary"/>.
    /// <see cref="AuditEntry.Hash"/> / <see cref="AuditEntry.PreviousHash"/> are left for the
    /// store to populate when the entry is appended.
    /// </summary>
    /// <param name="sender">Logical sender of the tool call (e.g. user agent).</param>
    /// <param name="receiver">Logical receiver of the tool call (e.g. assistant agent).</param>
    /// <param name="session">Session in which the denial occurred.</param>
    /// <param name="callerId">Identifier of the principal that attempted the call.</param>
    /// <param name="roles">Roles held by the caller at the time of the decision.</param>
    /// <param name="toolName">Name of the tool the caller attempted to invoke.</param>
    /// <param name="policyName">Name of the policy that produced the denial.</param>
    /// <param name="reason">Human-readable reason for the denial.</param>
    /// <param name="policyCode">Machine-readable code for the denial; defaults to <c>"policy_denied"</c>.
    /// Persists onto <see cref="AuditEntry.PolicyCode"/> and is also embedded into the summary string.</param>
    /// <returns>An <see cref="AuditEntry"/> ready to be appended to an <see cref="IAuditStore"/>.</returns>
    public static AuditEntry AuthorizationDeny(
        AgentId sender,
        AgentId receiver,
        SessionId session,
        string callerId,
        IReadOnlySet<string> roles,
        string toolName,
        string policyName,
        string reason,
        string policyCode = SentinelDenyCodes.PolicyDenied)
    {
        ArgumentNullException.ThrowIfNull(sender);
        ArgumentNullException.ThrowIfNull(receiver);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(roles);

        var summary = string.Format(
            CultureInfo.InvariantCulture,
            "Caller '{0}' (roles: [{1}]) denied for tool '{2}' by policy '{3}' [{4}] in session '{5}' ({6} -> {7}): {8}",
            callerId,
            string.Join(",", roles),
            toolName,
            policyName,
            policyCode,
            session.Value,
            sender.Value,
            receiver.Value,
            reason);

        return new AuditEntry(
            Id:           Guid.NewGuid().ToString("N"),
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         string.Empty,
            PreviousHash: null,
            Severity:     Severity.High,
            DetectorId:   AuthorizationDenyDetectorId,
            Summary:      summary,
            PolicyCode:   policyCode,
            SessionId:    session.Value);
    }
}
