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

        if (roles.OrganisationName is null)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        var authorization = services.GetRequiredService<IAuthorizationService>();
        if (!string.Equals(roles.OrganisationName, organisation, StringComparison.Ordinal)
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
        var events = (await store.ReadEventsAsync(organisation, http.RequestAborted).ConfigureAwait(false))
            .Where(e => (!blockedOnly || e.IsBlocked)
                && (node.Length == 0 || string.Equals(e.Node, node, StringComparison.Ordinal))
                && (session.Length == 0 || string.Equals(e.Session, session, StringComparison.Ordinal))
                && (from is null || e.At >= from) && (to is null || e.At <= to)
                && May(roles, http.User, e.Node ?? roles.OrganisationNodeId, e.Developer, own))
            .OrderBy(e => e.At).ToList();
        var gaps = blockedOnly
            ? []
            : (await store.ReadGapsAsync(organisation, http.RequestAborted).ConfigureAwait(false))
                .Where(g => (node.Length == 0 || string.Equals(g.Node, node, StringComparison.Ordinal))
                    && (from is null || g.ReceivedAt >= from) && (to is null || g.ReceivedAt <= to)
                    && May(roles, http.User, g.Node ?? roles.OrganisationNodeId, g.Developer, own)).ToList();
        return Results.Bytes(EventWriter.Write(events, blockedOnly ? null : gaps), "application/json");
    }

    private static bool May(NodeRoles roles, System.Security.Claims.ClaimsPrincipal user, string? node, string developer, string? own) =>
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
