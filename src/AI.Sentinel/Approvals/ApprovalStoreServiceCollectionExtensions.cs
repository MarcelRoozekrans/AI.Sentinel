using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Approvals;

/// <summary>DI registration of an approval store whose decisions reach the audit log.</summary>
public static class ApprovalStoreServiceCollectionExtensions
{
    /// <summary>
    /// The <see cref="IApprovalAdmin"/> of the active <see cref="IApprovalStore"/>, audited as AI.Sentinel's own
    /// surfaces resolve it, so it follows a store that replaced this registration. <see langword="null"/> when the
    /// active store has no admin surface.
    /// </summary>
    private static readonly Func<IServiceProvider, object> ResolveAdmin =
        sp => (ApprovalStoreAuditing.Resolve(sp) as IApprovalAdmin)!;

    /// <summary>
    /// Registers the store <paramref name="factory"/> builds as the approval store, and exposes it as
    /// <see cref="IApprovalStore"/>, and as <see cref="IApprovalAdmin"/> when <typeparamref name="TStore"/> implements
    /// it. When an <see cref="IAuditStore"/> is registered, both resolve to one wrapper over the store that records
    /// every approval decision taken through it in the audit log; without one they resolve to the store itself. The
    /// wrapper is built on first resolve, so this call may come before or after <c>AddAISentinel</c>, and it writes
    /// to whichever audit store is registered last. The built-in backends register through this method.
    /// </summary>
    /// <remarks>
    /// The store is registered as a keyed singleton under a private key, so resolve it through
    /// <see cref="IApprovalStore"/> or <see cref="IApprovalAdmin"/>; neither can be cast to
    /// <typeparamref name="TStore"/> while an audit store is registered. Approval-store backends are exclusive.
    /// <see cref="IApprovalAdmin"/> follows the active store: if a store without an admin surface replaces this
    /// registration, resolving <see cref="IApprovalAdmin"/> returns <see langword="null"/>, and
    /// <c>GetRequiredService</c> throws.
    /// </remarks>
    /// <typeparam name="TStore">The store type. <see cref="IApprovalAdmin"/> is registered when it implements it.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="factory">Builds the store, once. DI owns and disposes what it returns.</param>
    /// <returns>The same service collection, for chaining.</returns>
    /// <exception cref="InvalidOperationException">An <see cref="IApprovalStore"/> is already registered.</exception>
    public static IServiceCollection AddSentinelApprovalStore<TStore>(
        this IServiceCollection services, Func<IServiceProvider, TStore> factory)
        where TStore : class, IApprovalStore
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);

        if (ApprovalStoreAuditing.IsApprovalStoreRegistered(services))
        {
            throw new InvalidOperationException(
                "An IApprovalStore is already registered. Approval-store backends are exclusive — " +
                "remove the existing registration before wiring AddSentinelApprovalStore.");
        }

        // An earlier call's IApprovalStore may have been removed with RemoveAll, which leaves keyed descriptors and
        // other service types behind. This call's registrations replace them.
        for (var i = services.Count - 1; i >= 0; i--)
        {
            if (IsOwnDescriptor(services[i]))
            {
                services.RemoveAt(i);
            }
        }

        services.AddKeyedSingleton<IApprovalStore>(ApprovalStoreAuditing.InnerStoreKey, (sp, _) => factory(sp));
        services.AddSingleton(sp => new ApprovalStoreAuditing.RegisteredApprovalStore(
            ApprovalStoreAuditing.Wrap(sp, sp.GetRequiredKeyedService<IApprovalStore>(ApprovalStoreAuditing.InnerStoreKey))));
        services.AddSingleton<IApprovalStore>(sp => sp.GetRequiredService<ApprovalStoreAuditing.RegisteredApprovalStore>().Store);
        if (typeof(TStore).IsAssignableTo(typeof(IApprovalAdmin)))
        {
            services.Add(ServiceDescriptor.Singleton(typeof(IApprovalAdmin), ResolveAdmin));
        }
        return services;
    }

    private static bool IsOwnDescriptor(ServiceDescriptor d) =>
        (d.ServiceType == typeof(IApprovalStore) && d.IsKeyedService && ReferenceEquals(d.ServiceKey, ApprovalStoreAuditing.InnerStoreKey))
        || d.ServiceType == typeof(ApprovalStoreAuditing.RegisteredApprovalStore)
        || (d.ServiceType == typeof(IApprovalAdmin) && !d.IsKeyedService && ReferenceEquals(d.ImplementationFactory, ResolveAdmin));
}
