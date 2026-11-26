using AI.Sentinel.AspNetCore.Events;
using AI.Sentinel.AspNetCore.PolicyFolder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore;

/// <summary>Registers and maps the endpoints that receive events from developer machines and serve blocked calls and the audit
/// trail (ADR-240, ADR-247). Optional and off by default. Needs <see cref="PolicyFolderExtensions.AddAISentinelPolicyFolder"/>.</summary>
public static class ServerEventExtensions
{
    /// <summary>Registers the event store, the pseudonym key and the retention settings.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Sets <see cref="ServerEventOptions.PseudonymKey"/>, and optionally the policy name and retention.</param>
    public static IServiceCollection AddAISentinelServerEvents(this IServiceCollection services, Action<ServerEventOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ServerEventOptions>().Configure(configure);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IServerEventStore, InMemoryServerEventStore>();
        services.TryAddSingleton(sp =>
        {
            var key = sp.GetRequiredService<IOptions<ServerEventOptions>>().Value.PseudonymKey;
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new InvalidOperationException("ServerEventOptions.PseudonymKey is required to replace identities with codes.");
            }

            return new PseudonymKeys(key);
        });
        return services;
    }

    /// <summary>Maps the events endpoints. All use the host's authorization policy named in <see cref="ServerEventOptions.PolicyName"/>
    /// with the organisation as the resource, and the role on the node from the node configuration.
    /// <list type="bullet">
    /// <item><c>POST {pathPrefix}/ingest</c>: a batch from a developer machine. The organisation is the sender's, taken from the
    /// token; a batch that names another one is refused with 403 and nothing is stored.</item>
    /// <item><c>GET {pathPrefix}/{organisation}/blocked</c>: calls that were denied.</item>
    /// <item><c>GET {pathPrefix}/{organisation}/audit</c>: every event, and the reported gaps.</item>
    /// </list>
    /// Reads filter on <c>node</c>, <c>session</c>, <c>from</c> and <c>to</c> and show a code per developer, never a name. A team
    /// lead reads the events of their node, a developer their own.</summary>
    public static RouteGroupBuilder MapAISentinelServerEvents(
        this IEndpointRouteBuilder endpoints, string pathPrefix = "/ai-sentinel/events")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var group = endpoints.MapGroup(pathPrefix);
        group.MapPost("/ingest", (Delegate)EventIngest.IngestAsync);
        group.MapGet("/{organisation}/blocked", EventReads.BlockedAsync);
        group.MapGet("/{organisation}/audit", EventReads.AuditAsync);
        return group;
    }
}
