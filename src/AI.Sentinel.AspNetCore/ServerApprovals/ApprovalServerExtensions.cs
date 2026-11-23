using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.AspNetCore.ServerApprovals;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore;

/// <summary>Registers and maps the approval endpoints of the server part (#662). Optional and off by default. A team can run them on its
/// own, with no central product, and approve and deny over HTTP.</summary>
public static class ApprovalServerExtensions
{
    /// <summary>The default prefix of the endpoints. The <c>http</c> approval backend of the hook asks for it unless told otherwise.</summary>
    public const string DefaultPathPrefix = "/ai-sentinel/approvals";

    /// <summary>Registers the store of approval requests. Needs <see cref="AdminAuditExtensions.AddAISentinelAdminAudit"/>, which records
    /// each approve and deny, and <see cref="PolicyFolderExtensions.AddAISentinelPolicyFolder"/>, whose node configuration binds the roles.
    /// The requests are kept in memory.</summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddAISentinelApprovalServer(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(sp => new ServerApprovalStore(sp.GetRequiredService<TimeProvider>()));
        return services;
    }

    /// <summary>Maps the approval endpoints. All need a signed-in developer who satisfies the policy named in
    /// <see cref="PolicyFolderOptions.PolicyName"/> for the organisation. They answer 503 until a configuration has been published.
    /// <list type="bullet">
    /// <item><c>POST {pathPrefix}</c>: opens a request for the signed-in developer, or returns the open one of the same rule. The body
    /// carries the repository, the rule, the tool, the redacted tool input and the grant length.</item>
    /// <item><c>GET {pathPrefix}/{id}</c>: the state of a request, for its requester and for those who may decide it; 404 for anyone else.</item>
    /// <item><c>GET {pathPrefix}</c>: the pending requests the signed-in developer may decide; <c>?mine=true</c> lists their own.</item>
    /// <item><c>POST {pathPrefix}/{id}/approve</c> and <c>/deny</c>: an administrator, or the team lead of the node that owns the
    /// repository of the request, decides it. Nobody decides their own request: 403.</item>
    /// </list></summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="pathPrefix">The prefix of the endpoints.</param>
    public static RouteGroupBuilder MapAISentinelApprovalServer(this IEndpointRouteBuilder endpoints, string pathPrefix = DefaultPathPrefix)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var services = endpoints.ServiceProvider;
        var handlers = new ApprovalEndpoints(
            services.GetRequiredService<ServerApprovalStore>(),
            services.GetRequiredService<NodeRoles>(),
            services.GetRequiredService<AdminAuditLog>(),
            services.GetRequiredService<IOptions<PolicyFolderOptions>>(),
            pathPrefix.TrimEnd('/'));
        var group = endpoints.MapGroup(pathPrefix);
        group.MapPost("/", handlers.CreateAsync);
        group.MapGet("/", handlers.ListAsync);
        group.MapGet("/{id}", handlers.GetAsync);
        group.MapPost("/{id}/approve", handlers.ApproveAsync);
        group.MapPost("/{id}/deny", handlers.DenyAsync);
        return group;
    }
}
