using System.Text;
using System.Text.Json;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.AspNetCore.SessionControl;
using AI.Sentinel.ClaudeCode.Resident;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore;

/// <summary>Maps the endpoints that pause and release a session, and the event stream that carries them to the resident processes.
/// Optional and off by default; needs <see cref="PolicyFolderExtensions.AddAISentinelPolicyFolder"/> and <see cref="AdminAuditExtensions.AddAISentinelAdminAudit"/>.</summary>
public static class SessionControlExtensions
{
    private const int MaxReasonLength = 500;

    /// <summary>Maps the session control endpoints. All need a signed-in developer of the organisation, as the policy folder's endpoints do.
    /// <list type="bullet">
    /// <item><c>POST {pathPrefix}/{session}/pause</c>: body <c>{"repository": "...", "reason": "...", "until": "..."}</c>. Only an administrator,
    /// or a team lead of the node that owns the repository, may. 200 with the pause.</item>
    /// <item><c>POST {pathPrefix}/{session}/release</c>: lifts it, under the same rule on the repository the pause named. 204; 404 when none.</item>
    /// <item><c>GET {pathPrefix}</c>: the pauses in force on the nodes the caller leads.</item>
    /// <item><c>GET {pathPrefix}/events</c>: <c>text/event-stream</c> with a snapshot first, then <c>pause</c>, <c>release</c> and <c>configuration</c>
    /// events, and a heartbeat comment every <see cref="PolicyFolderOptions.SessionStreamHeartbeat"/>.</item>
    /// </list>
    /// A pause names a session and never a person. Each pause and release is written to the admin audit log with the channel <c>web</c>.</summary>
    public static RouteGroupBuilder MapAISentinelSessionControl(
        this IEndpointRouteBuilder endpoints, string pathPrefix = "/ai-sentinel/sessions")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var group = endpoints.MapGroup(pathPrefix);
        group.MapGet("/events", EventsAsync);
        group.MapGet(string.Empty, ListAsync);
        group.MapPost("/{session}/pause", PauseAsync);
        group.MapPost("/{session}/release", ReleaseAsync);
        return group;
    }

    private static async Task<IResult> EventsAsync(
        HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer,
        SessionControlHub hub, TimeProvider time)
    {
        var (failure, _) = await PolicyFolderExtensions.AdmitAsync(http, authorization, options, issuer).ConfigureAwait(false);
        if (failure is not null)
        {
            return failure;
        }

        http.Response.ContentType = "text/event-stream";
        http.Response.Headers.CacheControl = "no-cache";
        http.Response.Headers["X-Accel-Buffering"] = "no";
        var ct = http.RequestAborted;
        using var subscription = hub.Subscribe();
        using var heartbeat = new PeriodicTimer(options.Value.SessionStreamHeartbeat, time);
        try
        {
            await WriteAsync(http, new SseFrame(SessionEventNames.Snapshot,
                JsonSerializer.Serialize(subscription.Snapshot, SessionEventJsonContext.Default.SessionSnapshot)), ct).ConfigureAwait(false);
            var read = subscription.Events.WaitToReadAsync(ct).AsTask();
            var tick = heartbeat.WaitForNextTickAsync(ct).AsTask();
            while (true)
            {
                var done = await Task.WhenAny(read, tick).ConfigureAwait(false);
                if (done == tick)
                {
                    if (!await tick.ConfigureAwait(false))
                    {
                        break;
                    }

                    await http.Response.WriteAsync(": heartbeat\n\n", ct).ConfigureAwait(false);
                    await http.Response.Body.FlushAsync(ct).ConfigureAwait(false);
                    tick = heartbeat.WaitForNextTickAsync(ct).AsTask();
                    continue;
                }

                if (!await read.ConfigureAwait(false))
                {
                    break;
                }

                while (subscription.Events.TryRead(out var frame))
                {
                    await WriteAsync(http, frame, ct).ConfigureAwait(false);
                }

                read = subscription.Events.WaitToReadAsync(ct).AsTask();
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or ObjectDisposedException)
        {
            // The resident process went away, or the stream was closed because it fell behind: it reconnects to a fresh snapshot.
        }

        return Results.Empty;
    }

    private static async Task WriteAsync(HttpContext http, SseFrame frame, CancellationToken ct)
    {
        await http.Response.WriteAsync($"event: {frame.Event}\ndata: {frame.Data}\n\n", Encoding.UTF8, ct).ConfigureAwait(false);
        await http.Response.Body.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task<IResult> ListAsync(
        HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer,
        SessionControlHub hub, NodeRoles roles)
    {
        var (failure, _) = await PolicyFolderExtensions.AdmitAsync(http, authorization, options, issuer).ConfigureAwait(false);
        if (failure is not null)
        {
            return failure;
        }

        return Results.Json(
            hub.List().Where(h => roles.AllowsOnSession(http.User, NodeRole.TeamLead, h.Repository))
                .Select(h => new PauseListEntry(h.Pause.Session, h.Repository, h.Pause.Reason, h.Pause.Until)).ToArray(),
            SessionControlJsonContext.Default.PauseListEntryArray);
    }

    private static async Task<IResult> PauseAsync(
        string session, HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer,
        SessionControlHub hub, NodeRoles roles, AdminAuditLog audit, TimeProvider time)
    {
        var (failure, configuration) = await PolicyFolderExtensions.AdmitAsync(http, authorization, options, issuer).ConfigureAwait(false);
        if (failure is not null)
        {
            return failure;
        }

        var body = await ReadBodyAsync(http).ConfigureAwait(false);
        if (body is null || !IsIdentifier(session) || string.IsNullOrWhiteSpace(body.Repository) || !IsReason(body.Reason)
            || (body.Until is { } until && until <= time.GetUtcNow()))
        {
            return Results.StatusCode(StatusCodes.Status400BadRequest);
        }

        if (roles.DeveloperOf(http.User) is not { } actor || !roles.AllowsOnSession(http.User, NodeRole.TeamLead, body.Repository))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        // Recorded first: a pause that is not in the audit log does not take effect.
        await audit.RecordAsync(configuration!.Organisation, AdminAuditAction.Pause, actor, session, AdminAuditChannel.Web, http.RequestAborted).ConfigureAwait(false);
        return Results.Json(hub.Pause(session, body.Repository.Trim(), body.Reason, body.Until), SessionControlJsonContext.Default.PausedSession);
    }

    private static async Task<IResult> ReleaseAsync(
        string session, HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer,
        SessionControlHub hub, NodeRoles roles, AdminAuditLog audit)
    {
        var (failure, configuration) = await PolicyFolderExtensions.AdmitAsync(http, authorization, options, issuer).ConfigureAwait(false);
        if (failure is not null)
        {
            return failure;
        }

        if (!IsIdentifier(session))
        {
            return Results.StatusCode(StatusCodes.Status400BadRequest);
        }

        if (hub.Find(session) is not { } held)
        {
            return Results.StatusCode(StatusCodes.Status404NotFound);
        }

        if (roles.DeveloperOf(http.User) is not { } actor || !roles.AllowsOnSession(http.User, NodeRole.TeamLead, held.Repository))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        await audit.RecordAsync(configuration!.Organisation, AdminAuditAction.Release, actor, session, AdminAuditChannel.Web, http.RequestAborted).ConfigureAwait(false);
        _ = hub.Release(session);
        return Results.StatusCode(StatusCodes.Status204NoContent);
    }

    private static async Task<PauseRequestWire?> ReadBodyAsync(HttpContext http)
    {
        try
        {
            return await JsonSerializer.DeserializeAsync(http.Request.Body, SessionControlJsonContext.Default.PauseRequestWire, http.RequestAborted).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool IsIdentifier(string value)
    {
        try
        {
            AdminAuditEntry.CheckField(value, nameof(value));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsReason(string? reason) =>
        reason is null || (reason.Length <= MaxReasonLength && !reason.Any(char.IsControl));
}
