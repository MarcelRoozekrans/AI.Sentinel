using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using AI.Sentinel.AspNetCore.PolicyFolder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore.Events;

/// <summary>The read endpoints: blocked calls and the audit trail, filtered, per team and without names.</summary>
internal static class EventReads
{
    public static Task<IResult> BlockedAsync(string organisation, HttpContext http) => ReadAsync(organisation, http, blockedOnly: true);

    public static Task<IResult> AuditAsync(string organisation, HttpContext http) => ReadAsync(organisation, http, blockedOnly: false);

    private static async Task<IResult> ReadAsync(string organisation, HttpContext http, bool blockedOnly)
    {
        var services = http.RequestServices;
        var options = services.GetRequiredService<IOptions<ServerEventOptions>>().Value;
        var roles = services.GetRequiredService<NodeRoles>();
        if (http.User.Identity?.IsAuthenticated != true)
        {
            return Results.StatusCode(StatusCodes.Status401Unauthorized);
        }

        // One configuration answers the organisation check and every role check of this request.
        if (roles.Snapshot() is not { } current)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        var authorization = services.GetRequiredService<IAuthorizationService>();
        if (!string.Equals(current.Organisation, organisation, StringComparison.Ordinal)
            || !(await authorization.AuthorizeAsync(http.User, organisation, options.PolicyName).ConfigureAwait(false)).Succeeded)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var query = http.Request.Query;
        var node = query["node"].ToString();
        var session = query["session"].ToString();
        if (!TryTime(query["from"].ToString(), out var from) || !TryTime(query["to"].ToString(), out var to))
        {
            return Results.StatusCode(StatusCodes.Status400BadRequest);
        }

        var own = roles.DeveloperOf(http.User) is { } developer
            ? services.GetRequiredService<PseudonymKeys>().CodeFor(organisation, developer)
            : null;
        var store = services.GetRequiredService<IServerEventStore>();
        var stored = await store.ReadEventsAsync(organisation, http.RequestAborted).ConfigureAwait(false);
        var storedGaps = await store.ReadGapsAsync(organisation, http.RequestAborted).ConfigureAwait(false);
        var visibility = new TeamVisibility(current.Configuration, stored, storedGaps, options.MinimumTeamPeople);
        var events = stored
            .Select(e => (Event: e, Node: visibility.NodeFor(e.Node) ?? current.OrganisationNodeId))
            .Select(x => new ShownEvent(x.Event, x.Node, Own(own, x.Event.Developer) || visibility.ShowsName(x.Event, x.Node)))
            .Where(s => (!blockedOnly || s.Event.IsBlocked)
                && (node.Length == 0 || string.Equals(s.Node, node, StringComparison.Ordinal))
                && (session.Length == 0 || string.Equals(s.Event.Session, session, StringComparison.Ordinal))
                && (from is null || s.Event.At >= from) && (to is null || s.Event.At <= to)
                && May(current, http.User, s.Node, s.Event.Developer, own))
            .OrderBy(s => s.Event.At).ToList();
        var gaps = blockedOnly
            ? []
            : storedGaps
                .Select(g => new ShownGap(g, visibility.NodeFor(g.Node) ?? current.OrganisationNodeId, Own(own, g.Developer)))
                .Where(s => (node.Length == 0 || string.Equals(s.Node, node, StringComparison.Ordinal))
                    && (from is null || s.Gap.ReceivedAt >= from) && (to is null || s.Gap.ReceivedAt <= to)
                    && May(current, http.User, s.Node, s.Gap.Developer, own)).ToList();
        return Results.Bytes(EventWriter.Write(events, blockedOnly ? null : gaps), "application/json");
    }

    private static bool Own(string? own, string developer) => own is not null && string.Equals(own, developer, StringComparison.Ordinal);

    private static bool May(NodeRoleSnapshot roles, ClaimsPrincipal user, string? node, string developer, string? own) =>
        (own is not null && string.Equals(own, developer, StringComparison.Ordinal))
        || (node is not null && roles.Allows(user, NodeRole.TeamLead, node));

    private static bool TryTime(string text, out DateTimeOffset? value)
    {
        value = null;
        if (text.Length == 0)
        {
            return true;
        }

        if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
        {
            value = parsed.ToUniversalTime();
            return true;
        }

        return false;
    }
}
