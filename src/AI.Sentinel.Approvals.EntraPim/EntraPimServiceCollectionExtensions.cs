using AI.Sentinel.Approvals;
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Graph;

namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>DI registration for <see cref="EntraPimApprovalStore"/>.</summary>
public static class EntraPimServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="EntraPimApprovalStore"/> as the <see cref="IApprovalStore"/>
    /// for AI.Sentinel approval gates. Builds a <see cref="GraphServiceClient"/> using a
    /// <see cref="ChainedTokenCredential"/> by default (managed identity → workload
    /// identity → environment vars → Azure CLI). Operators can override the credential
    /// by registering a <see cref="TokenCredential"/> in DI BEFORE calling this extension.
    /// </summary>
    /// <remarks>
    /// Required Graph permissions (admin-consent in Entra):
    /// <list type="bullet">
    ///   <item><c>RoleManagement.Read.Directory</c></item>
    ///   <item><c>RoleManagement.ReadWrite.Directory</c></item>
    /// </list>
    /// All registrations are singletons — the Graph client is thread-safe and the PIM
    /// credential chain is long-lived. Throws <see cref="InvalidOperationException"/>
    /// if an <see cref="IApprovalStore"/> is already registered (approval-store backends
    /// are exclusive — accidental double-wiring is a misconfiguration, not a swap).
    /// </remarks>
    public static IServiceCollection AddSentinelEntraPimApprovalStore(
        this IServiceCollection services,
        Action<EntraPimOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        // Approval-store backends are exclusive — silently overwriting a prior registration
        // (e.g. AddSentinelSqliteStore + AddSentinelEntraPimApprovalStore) is almost always
        // a wiring bug. Fail fast with an operator-actionable message.
        if (services.Any(sd => sd.ServiceType == typeof(IApprovalStore)))
        {
            throw new InvalidOperationException(
                "An IApprovalStore is already registered. Approval-store backends are exclusive — " +
                "remove the existing registration before wiring AddSentinelEntraPimApprovalStore.");
        }

        // Build + validate options eagerly at registration time. Mirrors AddSentinelSqliteStore:
        // failures surface where the misconfiguration was authored, not on first request.
        var options = BuildOptions(configure);
        services.AddSingleton(options);

        // TryAddSingleton: operators who pre-register their own GraphServiceClient (e.g.
        // for tests, to share an SDK pipeline, or to plug in custom retry handlers) keep
        // their version. Same treatment for IGraphRoleClient — wrapping in retry/decorator
        // middleware is a legitimate extension point.
        services.TryAddSingleton<GraphServiceClient>(sp =>
        {
            // Operators can pre-register a TokenCredential to override the default chain
            // (e.g. for tests, on-behalf-of flows, or custom client-secret configs).
            var credential = sp.GetService<TokenCredential>() ?? BuildDefaultCredential();
            return new GraphServiceClient(
                credential,
                scopes: new[] { "https://graph.microsoft.com/.default" });
        });

        services.TryAddSingleton<IGraphRoleClient>(sp =>
            new MicrosoftGraphRoleClient(sp.GetRequiredService<GraphServiceClient>()));

        // IApprovalStore stays AddSingleton: last-write-wins is the right contract for
        // the headline approval store — operators explicitly opt in to this backend by
        // calling this extension, and the docs above document that semantics.
        services.AddSingleton<IApprovalStore>(sp =>
            new EntraPimApprovalStore(
                sp.GetRequiredService<IGraphRoleClient>(),
                sp.GetRequiredService<EntraPimOptions>()));

        return services;
    }

    private static EntraPimOptions BuildOptions(Action<EntraPimOptions> configure)
    {
        // TenantId is `required` at the type level but our public surface is the
        // Action<EntraPimOptions> configure delegate, so we seed an empty value here
        // and re-validate after the caller populates it.
        var opts = new EntraPimOptions { TenantId = string.Empty };
        configure(opts);
        if (string.IsNullOrWhiteSpace(opts.TenantId))
        {
            throw new InvalidOperationException(
                "EntraPimOptions.TenantId must be configured (Entra tenant GUID).");
        }
        return opts;
    }

    private static TokenCredential BuildDefaultCredential() => new ChainedTokenCredential(
        // System-assigned managed identity (the parameterless / clientId-less constructor
        // is obsolete in Azure.Identity 1.13+ — use ManagedIdentityId.SystemAssigned).
        new ManagedIdentityCredential(new ManagedIdentityCredentialOptions(ManagedIdentityId.SystemAssigned)),
        new WorkloadIdentityCredential(),
        new EnvironmentCredential(),
        new AzureCliCredential());
}
