using System.Collections.Concurrent;
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>
/// <see cref="IApprovalStore"/> backed by Microsoft Entra Privileged Identity Management.
/// Approval state is owned by PIM — this store does NOT implement <see cref="IApprovalAdmin"/>;
/// approvers act in the PIM portal, not via the AI.Sentinel dashboard.
/// </summary>
/// <remarks>
/// Mapping (design doc §7.3):
/// <list type="bullet">
///   <item><c>Provisioned</c> / <c>PendingProvisioning</c> with non-null <c>ExpiresAt</c>
///         → <see cref="ApprovalState.Active"/>.</item>
///   <item><c>PendingApproval</c>, <c>Granted</c>, <c>PendingScheduleCreation</c>
///         → <see cref="ApprovalState.Pending"/>.</item>
///   <item><c>Denied</c>, <c>Failed</c>, <c>Revoked</c>, <c>Canceled</c>
///         → <see cref="ApprovalState.Denied"/>.</item>
/// </list>
/// </remarks>
public sealed class EntraPimApprovalStore : IApprovalStore
{
    private readonly IGraphRoleClient _graph;
    private readonly EntraPimOptions _options;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, string> _roleIdCache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Fallback grant duration when the actual schedule expiry can't be read back.</summary>
    private static readonly TimeSpan FallbackGrantDuration = TimeSpan.FromMinutes(15);

    public EntraPimApprovalStore(IGraphRoleClient graph, EntraPimOptions options, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(options);
        _graph = graph;
        _options = options;
        _time = time ?? TimeProvider.System;

        // Seed the cache from configured role-name → roleId mappings (process-lifetime cache).
        foreach (var kvp in options.RoleNameToIdSeed)
            _roleIdCache[kvp.Key] = kvp.Value;
    }

    /// <inheritdoc/>
    public async ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(context);

        var now = _time.GetUtcNow();

        if (string.IsNullOrWhiteSpace(spec.BackendBinding))
            return new ApprovalState.Denied("ApprovalSpec.BackendBinding required for EntraPim", now);

        // Stage 2 follow-up (deferred): UPN fallback per design doc §7.4 — if caller.Id looks
        // like a UPN, resolve via GET /users/{UPN}. For now treat caller.Id as the AAD object id.
        var principalId = caller.Id;
        var roleName = spec.BackendBinding!;

        try
        {
            var roleId = await ResolveRoleIdCachedAsync(roleName, ct).ConfigureAwait(false);
            if (roleId is null)
                return new ApprovalState.Denied($"role '{roleName}' not found in tenant", now);

            // 1. Active grant?
            var schedule = await _graph.GetActiveAssignmentAsync(principalId, roleId, ct).ConfigureAwait(false);
            if (schedule is not null && IsActiveScheduleStatus(schedule.Status) && schedule.ExpiresAt is { } exp)
                return new ApprovalState.Active(exp);

            // 2. Eligible?
            var eligible = await _graph.IsEligibleAsync(principalId, roleId, ct).ConfigureAwait(false);
            if (!eligible)
                return new ApprovalState.Denied($"caller is not eligible for role '{roleName}'", now);

            // 3. Create activation request.
            var justification = !string.IsNullOrWhiteSpace(context.Justification)
                ? context.Justification!
                : $"AI agent invocation: {context.ToolName}";

            var requestId = await _graph
                .CreateActivationRequestAsync(principalId, roleId, spec.GrantDuration, justification, ct)
                .ConfigureAwait(false);

            return new ApprovalState.Pending(requestId, BuildPortalUrl(requestId), now);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Pragmatic catch-all per design doc §7.5. Task 2.4 will refine with typed exceptions
            // from MicrosoftGraphRoleClient (401/403/429/5xx classification).
            return new ApprovalState.Denied(ClassifyGraphError(ex), now);
        }
    }

    /// <inheritdoc/>
    public async ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeout > TimeSpan.Zero) cts.CancelAfter(timeout);
        var linked = cts.Token;

        var currentWait = _options.PollInterval;
        var maxBackoff = _options.PollMaxBackoff;
        ApprovalState lastState = new ApprovalState.Pending(
            requestId, BuildPortalUrl(requestId), _time.GetUtcNow());

        while (true)
        {
            if (linked.IsCancellationRequested)
                return lastState;

            try
            {
                await DelayWithJitterAsync(currentWait, linked).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return lastState;
            }

            RoleRequestSnapshot snap;
            try
            {
                snap = await _graph.GetRequestStatusAsync(requestId, linked).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Timeout from our linked CTS — return the most recent observed state.
                return lastState;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return new ApprovalState.Denied(ClassifyGraphError(ex), _time.GetUtcNow());
            }

            var mapped = await MapRequestStatusAsync(requestId, snap, linked).ConfigureAwait(false);
            switch (mapped)
            {
                case ApprovalState.Active:
                case ApprovalState.Denied:
                    return mapped;
                case ApprovalState.Pending:
                    lastState = mapped;
                    break;
            }

            // Exponential backoff capped at PollMaxBackoff.
            var doubled = TimeSpan.FromTicks(currentWait.Ticks * 2);
            currentWait = doubled > maxBackoff ? maxBackoff : doubled;
        }
    }

    private async ValueTask<ApprovalState> MapRequestStatusAsync(
        string requestId, RoleRequestSnapshot snap, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var status = snap.Status ?? string.Empty;

        // Provisioned → read back the schedule for the real ExpiresAt.
        if (IsActiveScheduleStatus(status))
        {
            if (!string.IsNullOrEmpty(snap.PrincipalId) && !string.IsNullOrEmpty(snap.RoleId))
            {
                var expires = await TryResolveScheduleExpiryAsync(snap.PrincipalId!, snap.RoleId!, ct)
                    .ConfigureAwait(false);
                return new ApprovalState.Active(expires);
            }
            // No identifiers on the snapshot → fallback (race during schedule provisioning).
            return new ApprovalState.Active(now + FallbackGrantDuration);
        }

        if (IsPendingStatus(status))
            return new ApprovalState.Pending(requestId, BuildPortalUrl(requestId), now);

        if (IsDeniedStatus(status))
        {
            var reason = !string.IsNullOrWhiteSpace(snap.FailureReason)
                ? snap.FailureReason!
                : $"PIM request status: {status}";
            return new ApprovalState.Denied(reason, now);
        }

        // Unknown status → treat as pending (avoid false denials on a status PIM later adds).
        return new ApprovalState.Pending(requestId, BuildPortalUrl(requestId), now);
    }

    /// <summary>
    /// Hook used by <see cref="WaitForDecisionAsync"/> when status flips to Provisioned, to
    /// resolve the real <c>ExpiresAt</c> from the schedule. Currently inline-fallback — the
    /// production <c>MicrosoftGraphRoleClient</c> (Task 2.4) will populate this on the snapshot.
    /// </summary>
    private async ValueTask<DateTimeOffset> TryResolveScheduleExpiryAsync(
        string principalId, string roleId, CancellationToken ct)
    {
        try
        {
            var snap = await _graph.GetActiveAssignmentAsync(principalId, roleId, ct).ConfigureAwait(false);
            if (snap?.ExpiresAt is { } exp) return exp;
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            // Swallow — schedule readback is best-effort. Task 2.4 will surface typed errors;
            // for now a transient Graph failure on the readback shouldn't fail the activation.
        }
        return _time.GetUtcNow() + FallbackGrantDuration;
    }

    private async ValueTask<string?> ResolveRoleIdCachedAsync(string displayName, CancellationToken ct)
    {
        if (_roleIdCache.TryGetValue(displayName, out var cached))
            return cached;

        var resolved = await _graph.ResolveRoleIdAsync(displayName, ct).ConfigureAwait(false);
        if (resolved is not null)
            _roleIdCache[displayName] = resolved;
        return resolved;
    }

    private async Task DelayWithJitterAsync(TimeSpan baseDelay, CancellationToken ct)
    {
        if (baseDelay <= TimeSpan.Zero)
        {
            await Task.Yield();
            return;
        }
        // ±20% jitter — Random.Shared is fine here: backoff jitter doesn't need crypto-grade
        // entropy and the per-call instance avoids contention.
#pragma warning disable MA0009 // Using Random.Shared on purpose for jitter.
        var jitterFactor = 1.0 + ((Random.Shared.NextDouble() * 0.4) - 0.2);
#pragma warning restore MA0009
        var ticks = (long)(baseDelay.Ticks * jitterFactor);
        if (ticks < TimeSpan.TicksPerMillisecond) ticks = TimeSpan.TicksPerMillisecond;
        await Task.Delay(TimeSpan.FromTicks(ticks), _time, ct).ConfigureAwait(false);
    }

    private static string BuildPortalUrl(string requestId) =>
        $"https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles/RequestId/{Uri.EscapeDataString(requestId)}";

    private static bool IsActiveScheduleStatus(string status) =>
        string.Equals(status, "Provisioned", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "PendingProvisioning", StringComparison.OrdinalIgnoreCase);

    private static bool IsPendingStatus(string status) =>
        string.Equals(status, "PendingApproval", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "Granted", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "PendingScheduleCreation", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "PendingAdminDecision", StringComparison.OrdinalIgnoreCase);

    private static bool IsDeniedStatus(string status) =>
        string.Equals(status, "Denied", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "Failed", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "Revoked", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "Canceled", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "Cancelled", StringComparison.OrdinalIgnoreCase);

    private static string ClassifyGraphError(Exception ex)
    {
        // Heuristic — Task 2.4 will replace this with typed exceptions from the Graph adapter.
        var msg = ex.Message ?? string.Empty;
        if (msg.Contains("401", StringComparison.Ordinal) ||
            msg.Contains("403", StringComparison.Ordinal) ||
            msg.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("Forbidden", StringComparison.OrdinalIgnoreCase))
        {
            return "RoleManagement.ReadWrite.Directory consent required";
        }
        return $"Graph error: {ex.GetType().Name}";
    }
}
