using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AI.Sentinel.Cli;

/// <summary>
/// Derives the approver identity for the dashboard from the socket peer address only, never from
/// forwarded headers. A trusted proxy may name the user in a header; a loopback peer may act as the
/// local OS user when the local approver is enabled.
/// </summary>
internal static class ApproverIdentityMiddleware
{
    internal const string TrustedProxyAuthType = "TrustedProxy";
    internal const string LocalApproverAuthType = "LocalApprover";
    private const int MaxUserLength = 256;
    private const string ProxyOnlyMessage = "This dashboard only accepts requests through its trusted proxy.";

    internal static IApplicationBuilder UseApproverIdentity(this IApplicationBuilder app, DashboardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(settings);

        var gate = !IPAddress.IsLoopback(settings.Bind);
        var proxies = settings.TrustedProxies;
        if (!gate && proxies.Count == 0 && !settings.LocalApprover)
            return app;

        var userHeader = settings.UserHeader;
        var localName = Environment.UserName;

        return app.Use(async (ctx, next) =>
        {
            var remote = Normalise(ctx.Connection.RemoteIpAddress);
            var isLoopback = remote is not null && IPAddress.IsLoopback(remote);
            var isProxy = remote is not null && Contains(proxies, remote);

            if (gate && !isLoopback && !isProxy)
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                ctx.Response.ContentType = "text/plain; charset=utf-8";
                await ctx.Response.WriteAsync(ProxyOnlyMessage, ctx.RequestAborted).ConfigureAwait(false);
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
            if (char.IsControl(c)) return false;
        name = trimmed;
        return true;
    }

    private static ClaimsPrincipal Principal(string name, string authenticationType) =>
        new(new ClaimsIdentity([new Claim(ClaimTypes.Name, name)], authenticationType));
}
