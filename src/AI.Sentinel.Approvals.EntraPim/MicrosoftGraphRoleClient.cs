using System.Collections;
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
internal sealed class MicrosoftGraphRoleClient : IGraphRoleClient
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

        // Top=2 to sniff for ambiguity. Custom Entra roles can collide with built-in
        // display names; blindly picking the first match would silently activate the
        // wrong role. EntraPimApprovalStore.EnsureRequestAsync catches the thrown
        // InvalidOperationException via ClassifyGraphError → Denied.
        var filter = $"displayName eq '{EscapeOData(displayName)}'";
        var page = await WithGraphRetryAsync(
            () => _graph.RoleManagement.Directory.RoleDefinitions
                .GetAsync(rc =>
                {
                    rc.QueryParameters.Filter = filter;
                    rc.QueryParameters.Top = 2;
                    rc.QueryParameters.Select = new[] { "id", "displayName" };
                }, ct),
            ct).ConfigureAwait(false);

        var matches = page?.Value;
        if (matches is null || matches.Count == 0)
            return null;
        if (matches.Count > 1)
        {
            throw new InvalidOperationException(
                $"Role display name '{displayName}' is ambiguous in this tenant ({matches.Count}+ matches). " +
                "Pre-resolve via EntraPimOptions.RoleNameToIdSeed.");
        }
        return matches[0].Id;
    }

    /// <inheritdoc/>
    public async ValueTask<RoleScheduleSnapshot?> GetActiveAssignmentAsync(
        string principalId, string roleId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(principalId);
        ArgumentException.ThrowIfNullOrWhiteSpace(roleId);

        // Filter by (principal, role) including both Provisioned and PendingProvisioning
        // statuses — EntraPimApprovalStore.IsActiveScheduleStatus treats both as Active,
        // so the schedule fetch must surface the same range or a schedule sitting in
        // PendingProvisioning would be invisible here.
        var filter =
            $"principalId eq '{EscapeOData(principalId)}' and " +
            $"roleDefinitionId eq '{EscapeOData(roleId)}' and " +
            "(status eq 'Provisioned' or status eq 'PendingProvisioning')";

        var page = await WithGraphRetryAsync(
            () => _graph.RoleManagement.Directory.RoleAssignmentSchedules
                .GetAsync(rc =>
                {
                    rc.QueryParameters.Filter = filter;
                    rc.QueryParameters.Top = 1;
                }, ct),
            ct).ConfigureAwait(false);

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

        var page = await WithGraphRetryAsync(
            () => _graph.RoleManagement.Directory.RoleEligibilitySchedules
                .GetAsync(rc =>
                {
                    rc.QueryParameters.Filter = filter;
                    rc.QueryParameters.Top = 1;
                    rc.QueryParameters.Select = new[] { "id" };
                }, ct),
            ct).ConfigureAwait(false);

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

        var created = await WithGraphRetryAsync(
            () => _graph.RoleManagement.Directory.RoleAssignmentScheduleRequests
                .PostAsync(body, cancellationToken: ct),
            ct).ConfigureAwait(false);

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

        var req = await WithGraphRetryAsync(
            () => _graph.RoleManagement.Directory.RoleAssignmentScheduleRequests[requestId]
                .GetAsync(cancellationToken: ct),
            ct).ConfigureAwait(false);

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

    /// <summary>
    /// Best-effort retry wrapper for transient Graph errors (429 + Retry-After,
    /// 503/504, transport-level <see cref="HttpRequestException"/>). Up to 3 retries,
    /// honouring <c>Retry-After</c> when present (seconds or HTTP-date), else 1/2/4s
    /// exponential fallback. After 3 retries the original exception propagates and
    /// <see cref="EntraPimApprovalStore"/> classifies it via <c>ClassifyGraphError</c>.
    /// </summary>
    /// <remarks>
    /// Untested at unit level — covered by future integration tests against real Graph.
    /// The reflective <c>ODataError</c> property reads avoid a hard reference to the
    /// generated SDK error namespace.
    /// </remarks>
    private static async Task<T> WithGraphRetryAsync<T>(Func<Task<T>> operation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(operation);
        const int maxAttempts = 3;
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await operation().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (attempt >= maxAttempts || !IsTransient(ex, attempt, out var delay))
                    throw;
                await Task.Delay(delay, ct).ConfigureAwait(false);
            }
        }
    }

    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2075",
        Justification = OdataReflectionJustification)]
    private static bool IsTransient(Exception ex, int attempt, out TimeSpan delay)
    {
        delay = TimeSpan.FromSeconds(1);
        if (ex is HttpRequestException)
        {
            delay = TimeSpan.FromSeconds(1 << Math.Min(attempt, 4));
            return true;
        }

        // ODataError lives in Microsoft.Graph.Models.ODataErrors. Reflective lookup avoids
        // pinning to the generated namespace and matches the approach used in
        // EntraPimApprovalStore.ClassifyGraphError.
        if (string.Equals(
            ex.GetType().FullName,
            "Microsoft.Graph.Models.ODataErrors.ODataError",
            StringComparison.Ordinal))
        {
            var statusProp = ex.GetType().GetProperty("ResponseStatusCode");
            var status = statusProp?.GetValue(ex) as int?;
            if (status is 429 or 503 or 504)
            {
                delay = TryParseRetryAfter(ex) ?? TimeSpan.FromSeconds(1 << Math.Min(attempt, 4));
                return true;
            }
        }
        return false;
    }

    private const string OdataReflectionJustification =
        "ODataError properties (ResponseStatusCode, ResponseHeaders) are stable Microsoft.Graph.Models.ODataErrors " +
        "members preserved by the SDK's own trim attributes. Reflection avoids a hard type reference so AI.Sentinel " +
        "stays decoupled from Graph SDK internals. AOT-published CLIs that don't use entra-pim never invoke this path.";

    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2075",
        Justification = OdataReflectionJustification)]
    private static TimeSpan? TryParseRetryAfter(Exception ex)
    {
        // Best-effort header read. Microsoft.Graph 5.x ODataError exposes ResponseHeaders
        // as IDictionary<string, IEnumerable<string>>; reflectively probe to avoid a hard dep.
        try
        {
            var headers = ex.GetType().GetProperty("ResponseHeaders")?.GetValue(ex) as IDictionary;
            if (headers is null)
                return null;
            if (headers["Retry-After"] is IEnumerable values)
            {
                foreach (var v in values)
                {
                    var s = v?.ToString();
                    if (string.IsNullOrEmpty(s)) continue;
                    if (int.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, out var seconds))
                        return TimeSpan.FromSeconds(seconds);
                    if (DateTimeOffset.TryParse(s, System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal, out var dt))
                    {
                        var until = dt - DateTimeOffset.UtcNow;
                        return until > TimeSpan.Zero ? until : TimeSpan.FromSeconds(1);
                    }
                }
            }
        }
        catch (Exception probeEx) when (probeEx is not OperationCanceledException)
        {
            // Best-effort header read — any reflection / parse failure falls back to the
            // fixed-delay path. Discard the exception explicitly so the linter sees it.
            _ = probeEx;
        }
        return null;
    }
}
