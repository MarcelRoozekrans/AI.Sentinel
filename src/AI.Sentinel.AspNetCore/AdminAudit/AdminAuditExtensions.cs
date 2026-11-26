using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.Profiles;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore;

/// <summary>Registers and maps the administrative audit log export. Optional and off by default.</summary>
public static class AdminAuditExtensions
{
    /// <summary>Registers the append-only administrative audit log and its export signer.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Sets <see cref="AdminAuditOptions.SigningKey"/> and optionally the policy name.</param>
    public static IServiceCollection AddAISentinelAdminAudit(this IServiceCollection services, Action<AdminAuditOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<AdminAuditOptions>().Configure(configure);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IAdminAuditStore, InMemoryAdminAuditStore>();
        services.TryAddSingleton(sp =>
        {
            var key = sp.GetRequiredService<IOptions<AdminAuditOptions>>().Value.SigningKey;
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new InvalidOperationException("AdminAuditOptions.SigningKey is required to sign an audit log export.");
            }
            return new AdminAuditLog(
                sp.GetRequiredService<IAdminAuditStore>(), ProfileSigningKeys.FromBase64(key), sp.GetRequiredService<TimeProvider>());
        });
        return services;
    }

    /// <summary>Maps <c>GET {pathPrefix}/{organisation}/export</c>, which returns the log of one organisation with a signed head.
    /// The host's authorization policy named in <see cref="AdminAuditOptions.PolicyName"/> is checked with the organisation as the resource.</summary>
    public static RouteGroupBuilder MapAISentinelAdminAudit(
        this IEndpointRouteBuilder endpoints, string pathPrefix = "/ai-sentinel/admin-audit")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var group = endpoints.MapGroup(pathPrefix);
        group.MapGet("/{organisation}/export", ExportAsync);
        return group;
    }

    private static async Task<IResult> ExportAsync(
        string organisation, HttpContext http, IAuthorizationService authorization, IOptions<AdminAuditOptions> options, AdminAuditLog log)
    {
        if (http.User.Identity?.IsAuthenticated != true)
        {
            return Results.StatusCode(StatusCodes.Status401Unauthorized);
        }
        var result = await authorization.AuthorizeAsync(http.User, organisation, options.Value.PolicyName).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        if (!IsAdministrator(http, organisation))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        var body = await log.ExportAsync(organisation, http.RequestAborted).ConfigureAwait(false);
        return Results.Bytes(body, "application/json");
    }

    /// <summary>When the policy folder is registered, the export needs the administrator role on the organisation from the node
    /// configuration as well as the host's policy. Without the policy folder there are no roles and the host policy decides alone.
    /// The organisation name and the role are read from one published configuration.</summary>
    private static bool IsAdministrator(HttpContext http, string organisation) =>
        http.RequestServices.GetService<NodeRoles>() is not { } roles || roles.IsAdministratorOf(http.User, organisation);
}
