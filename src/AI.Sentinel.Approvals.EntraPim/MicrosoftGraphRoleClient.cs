using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>
/// Production <see cref="IGraphRoleClient"/> implementation backed by the Microsoft.Graph
/// 5.x SDK. Talks to <c>/roleManagement/directory/*</c> endpoints under PIM.
/// </summary>
/// <remarks>
/// Constructed with a fully configured <see cref="GraphServiceClient"/> — credential
/// composition (e.g. <c>ChainedTokenCredential</c>) lives in the DI extension wired up
/// in Task 2.5. Exceptions thrown by the SDK (<c>ServiceException</c>, <c>ODataError</c>,
/// <c>HttpRequestException</c>, …) are intentionally NOT translated here; the calling
/// <see cref="EntraPimApprovalStore"/> classifies them into <c>ApprovalState.Denied</c>.
/// Cancellation propagates as <see cref="OperationCanceledException"/>.
/// </remarks>
// AOT/trimming note: Microsoft.Graph 5.x relies on Kiota-generated reflection-based
// JSON serialisation. IL2026/IL3050 warnings are expected at AOT-publish time but are
// surfaced/suppressed at the CLI bundling boundary in Task 5.6 — not here, so library
// builds remain clean for consumers that don't enable AOT.
public sealed class MicrosoftGraphRoleClient : IGraphRoleClient
{
    private readonly GraphServiceClient _graph;

    public MicrosoftGraphRoleClient(GraphServiceClient graph)
    {
        ArgumentNullException.ThrowIfNull(graph);
        _graph = graph;
    }

    /// <inheritdoc/>
    public async ValueTask<string?> ResolveRoleIdAsync(string displayName, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        var filter = $"displayName eq '{EscapeOData(displayName)}'";
        var page = await _graph.RoleManagement.Directory.RoleDefinitions
            .GetAsync(rc =>
            {
                rc.QueryParameters.Filter = filter;
                rc.QueryParameters.Top = 1;
                rc.QueryParameters.Select = new[] { "id", "displayName" };
            }, ct)
            .ConfigureAwait(false);

        var match = page?.Value;
        if (match is null || match.Count == 0)
            return null;
        return match[0].Id;
    }

    /// <inheritdoc/>
    public async ValueTask<RoleScheduleSnapshot?> GetActiveAssignmentAsync(
        string principalId, string roleId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(principalId);
        ArgumentException.ThrowIfNullOrWhiteSpace(roleId);

        // Filter by (principal, role) and Provisioned status. PendingProvisioning is
        // observed via the request status path — schedules surface here only once the
        // grant exists.
        var filter =
            $"principalId eq '{EscapeOData(principalId)}' and " +
            $"roleDefinitionId eq '{EscapeOData(roleId)}' and " +
            "status eq 'Provisioned'";

        var page = await _graph.RoleManagement.Directory.RoleAssignmentSchedules
            .GetAsync(rc =>
            {
                rc.QueryParameters.Filter = filter;
                rc.QueryParameters.Top = 1;
            }, ct)
            .ConfigureAwait(false);

        var first = page?.Value?.FirstOrDefault();
        if (first is null)
            return null;

        var status = first.Status ?? string.Empty;
        var expiresAt = ResolveScheduleExpiry(first.ScheduleInfo);
        return new RoleScheduleSnapshot(status, expiresAt);
    }

    /// <inheritdoc/>
    public async ValueTask<bool> IsEligibleAsync(string principalId, string roleId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(principalId);
        ArgumentException.ThrowIfNullOrWhiteSpace(roleId);

        var filter =
            $"principalId eq '{EscapeOData(principalId)}' and " +
            $"roleDefinitionId eq '{EscapeOData(roleId)}'";

        var page = await _graph.RoleManagement.Directory.RoleEligibilitySchedules
            .GetAsync(rc =>
            {
                rc.QueryParameters.Filter = filter;
                rc.QueryParameters.Top = 1;
                rc.QueryParameters.Select = new[] { "id" };
            }, ct)
            .ConfigureAwait(false);

        return page?.Value is { Count: > 0 };
    }

    /// <inheritdoc/>
    public async ValueTask<string> CreateActivationRequestAsync(
        string principalId, string roleId, TimeSpan duration, string justification, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(principalId);
        ArgumentException.ThrowIfNullOrWhiteSpace(roleId);
        ArgumentException.ThrowIfNullOrWhiteSpace(justification);
        if (duration <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(duration), duration, "Duration must be positive.");

        var body = new UnifiedRoleAssignmentScheduleRequest
        {
            Action = UnifiedRoleScheduleRequestActions.SelfActivate,
            PrincipalId = principalId,
            RoleDefinitionId = roleId,
            DirectoryScopeId = "/",
            Justification = justification,
            ScheduleInfo = new RequestSchedule
            {
                StartDateTime = DateTimeOffset.UtcNow,
                Expiration = new ExpirationPattern
                {
                    Type = ExpirationPatternType.AfterDuration,
                    // Kiota serialises TimeSpan as ISO-8601 duration (e.g. PT15M).
                    Duration = duration,
                },
            },
        };

        var created = await _graph.RoleManagement.Directory.RoleAssignmentScheduleRequests
            .PostAsync(body, cancellationToken: ct)
            .ConfigureAwait(false);

        var id = created?.Id;
        if (string.IsNullOrEmpty(id))
        {
            // Graph accepted the POST but didn't echo an id — defensive: surface as a
            // typed exception so the store classifies it. Should never happen in practice.
            throw new InvalidOperationException(
                "Graph accepted the activation request but returned no id.");
        }
        return id;
    }

    /// <inheritdoc/>
    public async ValueTask<RoleRequestSnapshot> GetRequestStatusAsync(string requestId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        var req = await _graph.RoleManagement.Directory.RoleAssignmentScheduleRequests[requestId]
            .GetAsync(cancellationToken: ct)
            .ConfigureAwait(false);

        if (req is null)
        {
            // 404 normally surfaces as ODataError; this guards the (theoretical) null
            // return path so the snapshot contract isn't violated.
            return new RoleRequestSnapshot(
                Status: "Unknown",
                FailureReason: $"Graph returned null for request '{requestId}'.",
                PrincipalId: null,
                RoleId: null);
        }

        var status = req.Status ?? string.Empty;
        // Microsoft.Graph 5.x's UnifiedRoleAssignmentScheduleRequest doesn't expose a
        // dedicated FailureReason field; the status itself ("Failed", "Denied", …) is
        // the canonical signal. EntraPimApprovalStore.MapRequestStatusAsync formats a
        // human-readable reason from the status when none is supplied here.
        return new RoleRequestSnapshot(
            Status: status,
            FailureReason: null,
            PrincipalId: req.PrincipalId,
            RoleId: req.RoleDefinitionId);
    }

    /// <summary>
    /// Resolves the effective expiry from a <see cref="RequestSchedule"/>. Prefers the
    /// explicit <c>EndDateTime</c>; falls back to <c>StartDateTime + Duration</c> when
    /// the schedule was provisioned with <c>AfterDuration</c>. Returns null when the
    /// SDK can't produce a definite instant — <see cref="EntraPimApprovalStore"/> falls
    /// back to a synthesised expiry in that case.
    /// </summary>
    private static DateTimeOffset? ResolveScheduleExpiry(RequestSchedule? scheduleInfo)
    {
        var exp = scheduleInfo?.Expiration;
        if (exp is null)
            return null;

        if (exp.EndDateTime is { } end)
            return end;

        if (exp.Duration is { } dur && scheduleInfo!.StartDateTime is { } start)
            return start + dur;

        return null;
    }

    /// <summary>
    /// Doubles single quotes per the OData v4 string-literal escaping rule. The Graph
    /// API does not accept other escaping (no backslashes, no URL encoding inside the
    /// literal). Display names with apostrophes (e.g. "Reviewer's Role") would
    /// otherwise break the filter.
    /// </summary>
    private static string EscapeOData(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
