using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace AI.Sentinel.AspNetCore;

/// <summary>
/// Reads the approval request id from the undecoded request target. Ids may contain %2F, ? and %,
/// which hosts and routing decode inconsistently in route values, so the {id} segment comes from
/// the raw target and is decoded exactly once.
/// </summary>
internal static class ApprovalRequestTarget
{
    /// <summary>
    /// The id segment of <paramref name="rawTarget"/>, decoded once, or null when there is none.
    /// <paramref name="trailingSegments"/> counts the segments after the id: 0 for the page, 1 for
    /// approve and deny. A trailing slash and the query string are ignored.
    /// </summary>
    internal static string? IdFromRawTarget(string? rawTarget, int trailingSegments)
    {
        if (string.IsNullOrEmpty(rawTarget)) return null;
        var end = rawTarget.IndexOf('?', StringComparison.Ordinal);
        var path = (end >= 0 ? rawTarget[..end] : rawTarget).TrimEnd('/');
        var segments = path.Split('/');
        var index = segments.Length - 1 - trailingSegments;
        return index >= 0 && segments[index].Length > 0 ? Uri.UnescapeDataString(segments[index]) : null;
    }

    /// <summary>The id from the raw target, falling back to the route value when the host gives none.</summary>
    internal static string IdOf(HttpContext ctx, int trailingSegments) =>
        IdFromRawTarget(ctx.Features.Get<IHttpRequestFeature>()?.RawTarget, trailingSegments)
        ?? (string?)ctx.Request.RouteValues["id"] ?? "";
}
