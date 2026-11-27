using System.Text.Json;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.ClaudeCode.ServerApprovals;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore.ServerApprovals;

/// <summary>The approval endpoints of the server part (#662). A developer opens and reads their own requests; an approver, who is an
/// administrator or the team lead of the node that owns the repository, lists and decides the others. Nobody decides their own request,
/// and every decision is written to the administrative audit log with its channel (#672).</summary>
internal sealed class ApprovalEndpoints(
    ServerApprovalStore store, NodeRoles roles, AdminAuditLog audit, IOptions<PolicyFolderOptions> options, string pathPrefix)
{
    /// <summary>The largest request body accepted; the tool input is the bulk of it.</summary>
    internal const int MaxBodyBytes = 256 * 1024;

    private const int MaxNameLength = 512;
    private const int MaxTextLength = 4096;
    private static readonly TimeSpan MaxGrant = TimeSpan.FromDays(30);

    public async Task<IResult> CreateAsync(HttpContext http, IAuthorizationService authorization)
    {
        if (await AdmitAsync(http, authorization).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (roles.DeveloperOf(http.User) is not { } requester)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var body = await ReadBodyAsync(http.Request, http.RequestAborted).ConfigureAwait(false);
        if (body is null)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        var request = Parse(body, ApprovalWireJsonContext.Default.ApprovalRequestWire);
        if (request is null || !IsValid(request))
        {
            return Results.StatusCode(StatusCodes.Status400BadRequest);
        }

        var ensured = store.Ensure(
            requester, request.Repository, request.Policy, request.Tool, request.Args ?? default, request.Justification, request.Reason, TimeSpan.FromSeconds(request.GrantSeconds));
        return StateResult(ensured.Approval, ensured.IsNew, http);
    }

    public async Task<IResult> GetAsync(string id, HttpContext http, IAuthorizationService authorization)
    {
        if (await AdmitAsync(http, authorization).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        // A request the caller may not see is not there for them: its existence is not told.
        return store.Find(id) is { } approval && roles.MaySeeDecision(http.User, approval.Repository, approval.Requester)
            ? StateResult(approval, isNew: false, http)
            : Results.StatusCode(StatusCodes.Status404NotFound);
    }

    public async Task<IResult> ListAsync(bool? mine, HttpContext http, IAuthorizationService authorization)
    {
        if (await AdmitAsync(http, authorization).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        IEnumerable<ServerApproval> requests;
        if (mine == true)
        {
            // The requester's own list follows the rule a read of one request does: on a repository no node owns, only an administrator.
            requests = roles.DeveloperOf(http.User) is { } developer
                ? store.OfRequester(developer).Where(a => roles.MaySeeDecision(http.User, a.Repository, a.Requester))
                : [];
        }
        else
        {
            requests = store.Pending().Where(a => roles.MayDecide(http.User, a.Repository, a.Requester));
        }

        var list = new ApprovalListWire { Requests = [.. requests.Select(a => ListItem(a))] };
        return Results.Json(list, ApprovalWireJsonContext.Default.ApprovalListWire);
    }

    public Task<IResult> ApproveAsync(string id, HttpContext http, IAuthorizationService authorization) => DecideAsync(id, approve: true, http, authorization);

    public Task<IResult> DenyAsync(string id, HttpContext http, IAuthorizationService authorization) => DecideAsync(id, approve: false, http, authorization);

    private async Task<IResult> DecideAsync(string id, bool approve, HttpContext http, IAuthorizationService authorization)
    {
        var (refused, admitted) = await AdmitWithAsync(http, authorization).ConfigureAwait(false);
        if (refused is not null)
        {
            return refused;
        }

        var body = await ReadBodyAsync(http.Request, http.RequestAborted).ConfigureAwait(false);
        if (body is null)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        var decision = body.Length == 0 ? new ApprovalDecisionWire() : Parse(body, ApprovalWireJsonContext.Default.ApprovalDecisionWire);
        var text = approve ? decision?.Note : decision?.Reason;
        if (decision is null || (text is { } t && t.Length > MaxTextLength))
        {
            return Results.StatusCode(StatusCodes.Status400BadRequest);
        }

        if (store.Find(id) is not { } request || !roles.MaySeeDecision(http.User, request.Repository, request.Requester))
        {
            return Results.StatusCode(StatusCodes.Status404NotFound);
        }

        // A requester sees their own request and still may not decide it, whatever their role (#674).
        if (!roles.MayDecide(http.User, request.Repository, request.Requester) || roles.DeveloperOf(http.User) is not { } decider)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var decided = store.Decide(id, approve, decider, string.IsNullOrWhiteSpace(text) ? null : text);
        if (decided is null)
        {
            return Results.StatusCode(StatusCodes.Status409Conflict);
        }

        // The decision is committed, so its entry is written even when the client has gone: a retry would get 409 and never record it.
        // The log names the decider and the request, and never the tool input.
        await audit.RecordAsync(
            admitted!.Organisation, approve ? AdminAuditAction.Approve : AdminAuditAction.Deny, decider, decided.Id, AdminAuditChannel.Web, CancellationToken.None).ConfigureAwait(false);
        return StateResult(decided, isNew: false, http);
    }

    /// <summary>The response that refuses a request that may not be served at all, or <see langword="null"/> when it may.</summary>
    private async Task<IResult?> AdmitAsync(HttpContext http, IAuthorizationService authorization) =>
        (await AdmitWithAsync(http, authorization).ConfigureAwait(false)).Refused;

    /// <summary>The refusal, or the node configuration the request was admitted with, so a decision is audited under the
    /// organisation the host policy was asked about even when the policy folder publishes during the request.</summary>
    private async Task<(IResult? Refused, NodeRoleSnapshot? Admitted)> AdmitWithAsync(HttpContext http, IAuthorizationService authorization)
    {
        if (http.User.Identity?.IsAuthenticated != true)
        {
            return (Results.StatusCode(StatusCodes.Status401Unauthorized), null);
        }

        // Without a published configuration there are no roles to decide with.
        if (roles.Snapshot() is not { } current)
        {
            return (Results.StatusCode(StatusCodes.Status503ServiceUnavailable), null);
        }

        var result = await authorization.AuthorizeAsync(http.User, current.Organisation, options.Value.PolicyName).ConfigureAwait(false);
        return result.Succeeded ? (null, current) : (Results.StatusCode(StatusCodes.Status403Forbidden), null);
    }

    private IResult StateResult(ServerApproval approval, bool isNew, HttpContext http)
    {
        var url = $"{http.Request.Scheme}://{http.Request.Host}{http.Request.PathBase}{pathPrefix}/{Uri.EscapeDataString(approval.Id)}";
        return Results.Json(StateOf(approval, isNew, url, store.Now), ApprovalWireJsonContext.Default.ApprovalStateWire);
    }

    internal static ApprovalStateWire StateOf(ServerApproval a, bool isNew, string url, DateTimeOffset now)
    {
        var (state, reason) = a.Status switch
        {
            ServerApprovalStatus.Pending => (ApprovalWireStates.Pending, null),
            ServerApprovalStatus.Approved when a.ExpiresAt is { } end && end > now => (ApprovalWireStates.Active, null),
            ServerApprovalStatus.Approved => (ApprovalWireStates.Denied, "expired"),
            _ => (ApprovalWireStates.Denied, a.Note ?? "denied"),
        };
        return new ApprovalStateWire
        {
            Id = a.Id,
            State = state,
            RequestedAt = a.RequestedAt,
            ExpiresAt = string.Equals(state, ApprovalWireStates.Active, StringComparison.Ordinal) ? a.ExpiresAt : null,
            DecidedAt = a.DecidedAt,
            Reason = reason,
            RequestReason = a.RequestReason,
            ApprovalUrl = url,
            IsNew = isNew,
        };
    }

    private ApprovalListItemWire ListItem(ServerApproval a)
    {
        var state = StateOf(a, isNew: false, url: string.Empty, store.Now);
        return new ApprovalListItemWire
        {
            Id = a.Id,
            Requester = a.Requester,
            Repository = a.Repository,
            Policy = a.Policy,
            Tool = a.Tool,
            Args = a.Args,
            Justification = a.Justification,
            RequestReason = a.RequestReason,
            RequestedAt = a.RequestedAt,
            State = state.State,
            DecidedAt = a.DecidedAt,
            Decider = a.Decider,
            Reason = state.Reason,
        };
    }

    private static bool IsValid(ApprovalRequestWire r) =>
        !string.IsNullOrWhiteSpace(r.Policy) && r.Policy.Length <= MaxNameLength
        && !string.IsNullOrWhiteSpace(r.Tool) && r.Tool.Length <= MaxNameLength
        && r.Repository.Length <= MaxNameLength
        && (r.Justification is null || r.Justification.Length <= MaxTextLength)
        && (r.Reason is null || r.Reason.Length <= MaxTextLength)
        && r.GrantSeconds > 0 && TimeSpan.FromSeconds(r.GrantSeconds) <= MaxGrant;

    private static T? Parse<T>(byte[] body, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize(body, info);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The body, or <see langword="null"/> when it is longer than <see cref="MaxBodyBytes"/>.</summary>
    private static async Task<byte[]?> ReadBodyAsync(HttpRequest request, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await request.Body.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxBodyBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
