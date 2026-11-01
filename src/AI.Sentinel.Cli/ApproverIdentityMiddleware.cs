using System.Globalization;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AI.Sentinel.Cli;

/// <summary>
/// Derives the approver identity for the dashboard from the socket peer address only, never from
/// forwarded headers. A trusted proxy may name the user in a header; a loopback peer may act as the
/// local OS user when the local approver is enabled. Every peer must also send a Host header the dashboard answers
/// to, which stops DNS rebinding.
/// </summary>
internal static class ApproverIdentityMiddleware
{
    internal const string TrustedProxyAuthType = "TrustedProxy";
    internal const string LocalApproverAuthType = "LocalApprover";
    private const int MaxUserLength = 256;
    private const string LocalHostOnlyMessage = "This dashboard only accepts requests addressed to localhost.";
    private const string ProxyHostMessage = "This dashboard only accepts requests for its configured host names.";
    private const string ProxyOnlyMessage = "This dashboard only accepts requests through its trusted proxy.";

    internal static IApplicationBuilder UseApproverIdentity(this IApplicationBuilder app, DashboardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(settings);

        var gate = !IPAddress.IsLoopback(settings.Bind);
        if (settings.LocalApprover && (gate || settings.TrustedProxies.Count > 0))
            throw new ArgumentException(
                "The local approver requires a loopback bind and no trusted proxies.", nameof(settings));
        var proxies = settings.TrustedProxies;
        // nginx proxy_pass sends the upstream address as Host, so the bind address itself is a name the proxy may use.
        var publicHosts = settings.Bind.Equals(IPAddress.Any) || settings.Bind.Equals(IPAddress.IPv6Any)
            ? settings.PublicHosts
            : [.. settings.PublicHosts, BindLiteral(settings.Bind)];
        var userHeader = settings.UserHeader;
        var localName = Environment.UserName;

        return app.Use(async (ctx, next) =>
        {
            var remote = Normalise(ctx.Connection.RemoteIpAddress);
            var isLoopback = remote is not null && IPAddress.IsLoopback(remote);
            var isProxy = remote is not null && Contains(proxies, remote);

            if (gate && !isLoopback && !isProxy)
            {
                await RejectAsync(ctx, ProxyOnlyMessage).ConfigureAwait(false);
                return;
            }

            // Every peer, a same-host proxy included, must send a host name this dashboard answers to.
            if (!IsLocalHost(ctx.Request.Host) && !(isProxy && IsPublicHost(ctx.Request.Host, publicHosts)))
            {
                await RejectAsync(ctx, isProxy ? ProxyHostMessage : LocalHostOnlyMessage).ConfigureAwait(false);
                return;
            }

            if (isProxy)
            {
                if (TryReadUser(ctx.Request, userHeader, out var name))
                    ctx.User = Principal(name, TrustedProxyAuthType);
            }
            else if (settings.LocalApprover && isLoopback)
            {
                ctx.User = Principal(localName, LocalApproverAuthType);
            }

            await next(ctx).ConfigureAwait(false);
        });
    }

    // Defends against DNS rebinding: a rebound hostname reaches loopback with a foreign Host header.
    private static bool IsLocalHost(HostString host) =>
        host.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
        || host.Host is "127.0.0.1" or "[::1]";

    private static string BindLiteral(IPAddress bind) =>
        bind.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{bind}]" : bind.ToString();

    private static bool IsPublicHost(HostString host, IReadOnlyList<string> publicHosts)
    {
        for (var i = 0; i < publicHosts.Count; i++)
            if (host.Host.Equals(publicHosts[i], StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static async Task RejectAsync(HttpContext ctx, string message)
    {
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync(message, ctx.RequestAborted).ConfigureAwait(false);
    }

    private static IPAddress? Normalise(IPAddress? address) =>
        address is { IsIPv4MappedToIPv6: true } ? address.MapToIPv4() : address;

    private static bool Contains(IReadOnlyList<IPNetwork> networks, IPAddress address)
    {
        for (var i = 0; i < networks.Count; i++)
            if (networks[i].Contains(address)) return true;
        return false;
    }

    private static bool TryReadUser(HttpRequest request, string header, out string name)
    {
        name = string.Empty;
        if (!request.Headers.TryGetValue(header, out var values) || values.Count != 1) return false;
        var trimmed = values[0]?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > MaxUserLength) return false;
        foreach (var c in trimmed)
            if (char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format) return false;
        name = trimmed;
        return true;
    }

    private static ClaimsPrincipal Principal(string name, string authenticationType) =>
        new(new ClaimsIdentity([new Claim(ClaimTypes.Name, name)], authenticationType));
}
