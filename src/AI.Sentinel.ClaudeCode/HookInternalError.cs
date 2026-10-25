using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Domain;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// What the Claude Code and Copilot hook CLIs do when they cannot evaluate a PreToolUse call: they block it,
/// with the error as the reason, and record an <c>AUTHZ-DENY</c> entry with the
/// <see cref="SentinelDenyCodes.InternalError"/> code. A hook that let the call run instead would turn a broken
/// approval config, or any bug in the hook, into a tool call that skipped every check (#478).
/// </summary>
internal static class HookInternalError
{
    /// <summary>The policy name the audit entry carries; no configured policy took the decision.</summary>
    internal const string PolicyName = "sentinel-internal";

    /// <summary>The start of every internal-error block reason.</summary>
    internal const string Prefix = "Sentinel internal error:";

    /// <summary>The block reason for an unexpected exception.</summary>
    internal static string Reason(Exception ex) =>
        $"{Prefix} {ex.GetType().Name}: {ex.Message}";

    /// <summary>The block reason for a <c>SENTINEL_APPROVAL_CONFIG</c> that failed to load or validate.</summary>
    internal static string ApprovalConfigReason(string path, Exception ex) =>
        $"{Prefix} approval config '{path}' could not be loaded: {ex.Message}";

    /// <summary>The block reason for a PreToolUse whose input names no tool while authorization is configured.</summary>
    internal const string MissingToolNameReason = Prefix + " PreToolUse input has no tool name";

    /// <summary>True when <paramref name="guard"/> can refuse a call, so a call it cannot evaluate must be blocked.
    /// A guard other than the default one was registered on purpose and counts as configured.</summary>
    internal static bool Authorizes(IToolCallGuard guard) => guard is not DefaultToolCallGuard { CanRefuse: false };

    /// <summary>The block reason for stdin that is not valid JSON, or is JSON <c>null</c>.</summary>
    internal static string StdinReason(Exception ex) =>
        ex is JsonException
            ? $"{Prefix} malformed stdin JSON: {ex.Message}"
            : $"{Prefix} empty stdin JSON: {ex.Message}";

    /// <summary>Records the block, best effort: the call is blocked either way and the exit code must not change, so a
    /// failure is returned as a problem for the CLI to report with its other audit problems, and <c>null</c> otherwise.</summary>
    internal static async Task<string?> TryAuditAsync(
        IAuditStore store, IReadOnlyList<IAuditForwarder> forwarders, string? toolName, string sessionId, string reason)
    {
        try
        {
            var entry = BuildAuditEntry(AnonymousSecurityContext.Instance, toolName, sessionId, reason);
            await store.AppendAndForwardAsync(entry, [.. forwarders], CancellationToken.None).ConfigureAwait(false);
            return null;
        }
#pragma warning disable CA1031 // Best effort: the call is blocked whether or not the entry is written.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return $"The internal-error block was not recorded: {ex.GetType().Name}: {ex.Message}";
        }
    }

    /// <summary>The <c>AUTHZ-DENY</c> entry for an internal-error block, with the tool <c>unknown</c> when the input
    /// names none and a new session id when it has none.</summary>
    internal static AuditEntry BuildAuditEntry(ISecurityContext caller, string? toolName, string sessionId, string reason)
    {
        var tool = string.IsNullOrWhiteSpace(toolName) ? "unknown" : toolName;
        return AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
            receiver: new AgentId(tool),
            session: new SessionId(string.IsNullOrWhiteSpace(sessionId) ? Guid.NewGuid().ToString("N") : sessionId),
            callerId: caller.Id,
            roles: caller.Roles,
            toolName: tool,
            policyName: PolicyName,
            reason: reason,
            policyCode: SentinelDenyCodes.InternalError);
    }
}
