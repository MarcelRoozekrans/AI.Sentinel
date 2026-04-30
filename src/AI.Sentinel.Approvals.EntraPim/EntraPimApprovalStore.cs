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
    private readonly Func<double> _jitterSource;
    private readonly string _portalBaseUrl;
    private readonly ConcurrentDictionary<string, string> _roleIdCache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Fallback grant duration when the actual schedule expiry can't be read back.</summary>
    private static readonly TimeSpan FallbackGrantDuration = TimeSpan.FromMinutes(15);

    /// <remarks>
    /// Constructor is internal because <see cref="IGraphRoleClient"/> is internal —
    /// production wiring goes through <c>AddSentinelEntraPimApprovalStore</c>.
    /// Tests construct directly via <c>InternalsVisibleTo</c>.
    /// </remarks>
    internal EntraPimApprovalStore(
        IGraphRoleClient graph,
        EntraPimOptions options,
        TimeProvider? time = null,
        Func<double>? jitterSource = null)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(options);
        _graph = graph;
        _options = options;
        _time = time ?? TimeProvider.System;
        // Random.Shared.NextDouble is the production default — backoff jitter doesn't
        // need crypto-grade entropy. Tests can inject a deterministic source.
#pragma warning disable MA0009 // Using Random.Shared on purpose for jitter.
        _jitterSource = jitterSource ?? Random.Shared.NextDouble;
#pragma warning restore MA0009

        // Strip a trailing slash on the configured portal base so concatenation produces
        // a clean URL regardless of whether the operator wrote "https://portal.azure.us"
        // or "https://portal.azure.us/".
        var basePortal = options.PortalBaseUrl ?? "https://portal.azure.com";
        _portalBaseUrl = basePortal.TrimEnd('/');

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

        // Caller-identity guard: see RejectIfNotGuid (§7.4 — UPN fallback is a Stage 2 follow-up).
        if (RejectIfNotGuid(caller.Id, now) is { } guardDenied)
            return guardDenied;

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
            // Pragmatic catch-all per design doc §7.5. ClassifyGraphError inspects the
            // typed exception (ODataError/HttpRequestException) and returns a Denied
            // ApprovalState with operator-actionable context.
            return ClassifyGraphError(ex, "EnsureRequest");
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

            // Read FIRST, then delay. This avoids paying a full PollInterval of latency
            // on the auto-approve case — when the activation is provisioned immediately
            // (no admin gate), the first read returns Active and we exit without sleeping.
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
                return ClassifyGraphError(ex, "WaitForDecision");
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

            // Pending — delay before the next read, with exponential backoff capped at
            // PollMaxBackoff. Cancellation during the delay returns the most recent state.
            try
            {
                await DelayWithJitterAsync(currentWait, linked).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return lastState;
            }

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
        // ±20% jitter — defaults to Random.Shared.NextDouble; tests inject deterministic
        // sources via the EntraPimApprovalStore ctor's optional jitterSource parameter.
        var jitterFactor = 1.0 + ((_jitterSource() * 0.4) - 0.2);
        var ticks = (long)(baseDelay.Ticks * jitterFactor);
        if (ticks < TimeSpan.TicksPerMillisecond) ticks = TimeSpan.TicksPerMillisecond;
        await Task.Delay(TimeSpan.FromTicks(ticks), _time, ct).ConfigureAwait(false);
    }

    private string BuildPortalUrl(string requestId) =>
        $"{_portalBaseUrl}/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles/RequestId/{Uri.EscapeDataString(requestId)}";

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
        string.Equals(status, "Cancelled", StringComparison.OrdinalIgnoreCase) ||
        // PIM corner case (design doc §7.3): the literal status string "AdminApproved"
        // means "approver granted, but the schedule failed to provision" — i.e. the
        // request is terminal-failed even though the name reads positive. Treat as denied.
        string.Equals(status, "AdminApproved", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Caller-identity guard: <see cref="ISecurityContext.Id"/> MUST be the AAD object ID
    /// (GUID). If a UPN or other shape leaks through, Graph silently returns empty results
    /// and the store reports "caller is not eligible" — confusing and misleading. We fail
    /// fast with an operator-actionable message. UPN fallback (design doc §7.4) is a
    /// Stage 2 follow-up; once implemented, this guard relaxes to accept UPN-shaped IDs.
    /// </summary>
    /// <returns><c>null</c> when the id is a valid GUID, else a <see cref="ApprovalState.Denied"/>.</returns>
    private static ApprovalState.Denied? RejectIfNotGuid(string callerId, DateTimeOffset now)
    {
        if (Guid.TryParse(callerId, out _))
            return null;
        return new ApprovalState.Denied(
            $"ISecurityContext.Id must be an AAD object ID (GUID) for EntraPim; received '{callerId}'. " +
            "UPN-shaped IDs are not yet supported — see design doc §7.4 (UPN fallback is a Stage 2 follow-up).",
            now);
    }

    private ApprovalState ClassifyGraphError(Exception ex, string contextLabel)
    {
        // Microsoft.Graph throws ODataError (Microsoft.Graph.Models.ODataErrors.ODataError)
        // with ResponseStatusCode populated. We use reflection rather than a hard reference
        // to avoid pulling additional Graph types into our public surface. Falls back to
        // HttpRequestException's StatusCode when the SDK throws at the transport layer.
        var statusCode = ex switch
        {
            _ when string.Equals(
                ex.GetType().FullName,
                "Microsoft.Graph.Models.ODataErrors.ODataError",
                StringComparison.Ordinal) => GetResponseStatusCode(ex),
            HttpRequestException hre => (int?)hre.StatusCode,
            _ => null,
        };

        var now = _time.GetUtcNow();
        return statusCode switch
        {
            401 or 403 => new ApprovalState.Denied(
                $"Graph access denied at {contextLabel}: RoleManagement.ReadWrite.Directory consent likely missing. " +
                $"({ex.GetType().Name}: {Truncate(ex.Message ?? string.Empty, 200)})",
                now),
            429 => new ApprovalState.Denied(
                $"Graph rate-limited at {contextLabel} (3 retries exhausted).",
                now),
            _ => new ApprovalState.Denied(
                $"Graph error at {contextLabel}: {ex.GetType().Name}: {Truncate(ex.Message ?? string.Empty, 200)}",
                now),
        };
    }

    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2075",
        Justification =
        "ODataError.ResponseStatusCode is a stable Microsoft.Graph.Models.ODataErrors property " +
        "preserved by the SDK's own trim attributes. Reflection avoids a hard type reference so " +
        "AI.Sentinel stays decoupled from Graph SDK internals. AOT-published CLIs that don't use " +
        "entra-pim never invoke this path.")]
    private static int? GetResponseStatusCode(Exception ex)
    {
        // ODataError exposes ResponseStatusCode as int. Reflection avoids a hard ref.
        var prop = ex.GetType().GetProperty("ResponseStatusCode");
        return prop?.GetValue(ex) is int code ? code : null;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
