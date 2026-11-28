using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using AI.Sentinel.AspNetCore.PolicyFolder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore.Events;

/// <summary>The ingest endpoint: authorisation, allowlist, codes, deduplication and retention.</summary>
internal static class EventIngest
{
    private static string OrganisationOf(ClaimsPrincipal user, NodeRoleSnapshot current, ServerEventOptions options) =>
        user.FindFirst(options.OrganisationClaim)?.Value is { Length: > 0 } claim ? claim : current.Organisation;

    public static async Task<IResult> IngestAsync(HttpContext http)
    {
        var services = http.RequestServices;
        var options = services.GetRequiredService<IOptions<ServerEventOptions>>().Value;
        var roles = services.GetRequiredService<NodeRoles>();
        if (http.User.Identity?.IsAuthenticated != true)
        {
            return Results.StatusCode(StatusCodes.Status401Unauthorized);
        }

        // The organisation is read once, so the sender is compared with the configuration of one version.
        if (roles.Snapshot() is not { } current)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        var sender = OrganisationOf(http.User, current, options);
        if (!string.Equals(sender, current.Organisation, StringComparison.Ordinal))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var admitted = await services.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(http.User, sender, options.PolicyName).ConfigureAwait(false);
        if (!admitted.Succeeded || roles.DeveloperOf(http.User) is not { } developer)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var (batch, failure) = await ReadBatchAsync(http, options.MaxBatchBytes).ConfigureAwait(false);
        if (failure is not null)
        {
            return failure;
        }

        if (!string.Equals(batch!.Organisation, sender, StringComparison.Ordinal))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var code = services.GetRequiredService<PseudonymKeys>().CodeFor(sender, developer);
        return await StoreAsync(services, options, current, batch, sender, code, http.RequestAborted).ConfigureAwait(false);
    }

    private static async Task<(ParsedBatch? Batch, IResult? Failure)> ReadBatchAsync(HttpContext http, int limit)
    {
        if (http.Request.ContentLength > limit)
        {
            return (null, Results.StatusCode(StatusCodes.Status413PayloadTooLarge));
        }

        try
        {
            using var document = await JsonDocument.ParseAsync(
                new LimitedStream(http.Request.Body, limit), cancellationToken: http.RequestAborted).ConfigureAwait(false);
            return EventBatchReader.Read(document.RootElement) is { } batch
                ? (batch, null)
                : (null, Results.StatusCode(StatusCodes.Status400BadRequest));
        }
        catch (JsonException)
        {
            return (null, Results.StatusCode(StatusCodes.Status400BadRequest));
        }
        catch (InvalidDataException)
        {
            return (null, Results.StatusCode(StatusCodes.Status413PayloadTooLarge));
        }
    }

    private static async Task<IResult> StoreAsync(
        IServiceProvider services, ServerEventOptions options, NodeRoleSnapshot current, ParsedBatch batch, string sender, string code, CancellationToken ct)
    {
        var store = services.GetRequiredService<IServerEventStore>();
        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();
        var accepted = 0;
        var duplicates = 0;
        var dropped = new Dictionary<string, int>(batch.Dropped, StringComparer.Ordinal);
        foreach (var e in batch.Events)
        {
            // Reason text only comes with detailed logging, which the node settles in the configuration the sender was admitted
            // with; without it the text is dropped, not kept.
            var reason = e.Reason;
            if (reason is not null && !current.DetailedLogging(e.Node))
            {
                reason = null;
                dropped["reason"] = dropped.GetValueOrDefault("reason") + 1;
            }

            var stored = new ServerEvent(
                e.Id!, sender, code, e.At ?? now, now, e.ToolKind!, e.Outcome!, e.Policies ?? [], e.PolicyVersion, e.Decided, e.Node,
                e.Cli, e.Session, e.Detector, e.Severity, e.Redactions, reason,
                current.ShowsNames(e.Node) ? ServerEvent.WithNames : ServerEvent.TeamsOnly);
            if (await store.AddAsync(stored, ct).ConfigureAwait(false))
            {
                accepted++;
            }
            else
            {
                duplicates++;
            }
        }

        if (batch.Gap is { } gap)
        {
            await store.AddGapAsync(new ServerEventGap(sender, code, gap.Node, gap.Pruned, now, gap.Id, gap.Cause), ct).ConfigureAwait(false);
        }

        await store.AddDroppedAsync(sender, dropped, ct).ConfigureAwait(false);
        var retention = options.RetentionOf(sender);
        await store.PruneAsync(
            sender, now.AddDays(-retention.EventDays), DateOnly.FromDateTime(now.UtcDateTime.AddMonths(-retention.DailyCountMonths)), ct)
            .ConfigureAwait(false);
        return Results.Text(
            string.Create(CultureInfo.InvariantCulture,
                $"{{\"accepted\":{accepted},\"duplicates\":{duplicates},\"rejected\":{batch.Rejected},\"dropped_fields\":{dropped.Count}}}"),
            "application/json");
    }
}
