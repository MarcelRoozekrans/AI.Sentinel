using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Notifications;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Approvals.Configuration;

/// <summary>
/// Translates an <see cref="ApprovalConfig"/> into <see cref="SentinelOptions"/> bindings
/// (via <c>opts.RequireApproval</c>) and reports which backend the config selected so CLIs
/// can dispatch to the correct <c>AddSentinel*ApprovalStore</c> DI extension.
/// </summary>
/// <remarks>
/// This type lives in core and never references backend-specific packages directly. CLIs
/// import the EntraPim / Sqlite packages and switch on the returned <see cref="ApprovalBackendKind"/>.
/// </remarks>
internal static class ApprovalBackendSelector
{
    /// <summary>
    /// Adds <c>opts.RequireApproval(toolPattern, ...)</c> bindings for every entry in
    /// <see cref="ApprovalConfig.Tools"/>. Callers that need the backend kind should call
    /// <see cref="GetBackend"/> separately — historically this method also returned the kind,
    /// but every caller now reads it via <c>GetBackend</c> BEFORE calling <c>Configure</c>
    /// so they can pre-register the backend store.
    /// </summary>
    public static void Configure(SentinelOptions opts, ApprovalConfig config)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(config);

        foreach (var (toolPattern, entries) in config.Tools)
        {
            // One RequireApproval call per entry, in order: the bindings share the pattern, so they
            // form one rule group and are named approval:<pattern>, approval:<pattern>[1], ...
            foreach (var toolConfig in entries)
            {
                var grantMinutes = toolConfig.GrantMinutes ?? config.DefaultGrantMinutes;
                var requireJustification = toolConfig.RequireJustification ?? true;

                opts.RequireApproval(toolPattern, spec =>
                {
                    spec.GrantDuration = TimeSpan.FromMinutes(grantMinutes);
                    spec.RequireJustification = requireJustification;
                    spec.BackendBinding = toolConfig.Role;
                    spec.GrantScope = toolConfig.GrantScope;
                    foreach (var (path, pattern) in toolConfig.When) spec.WhenArgument(path, pattern);
                });
            }
        }
    }

    /// <summary>
    /// Registers the <see cref="ApprovalNotifierSettings"/> when <paramref name="config"/> sets <c>notifyUrl</c>, so
    /// every resolved approval store posts a webhook for a new request. Does nothing otherwise, or when <paramref name="config"/> is null.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="config">The approval config, or <see langword="null"/> for none.</param>
    /// <param name="warn">
    /// Where the notifier's warnings go, such as a failed POST, or <see langword="null"/> for nowhere. The CLIs register
    /// no logging stack, so without this a webhook failure would go unseen. Only the notifier's warnings reach it.
    /// </param>
    internal static void AddNotifier(IServiceCollection services, ApprovalConfig? config, Action<string>? warn = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (config is null)
        {
            return;
        }

        var settings = ApprovalNotifierSettings.FromConfig(config);
        if (settings is not null)
        {
            services.AddSingleton(settings);
            if (warn is not null)
            {
                services.AddSingleton<ILogger<NotifyingApprovalStore>>(new WarningSinkLogger(warn));
            }
        }
    }

    /// <summary>
    /// Returns the backend kind without configuring bindings. CLIs call this BEFORE
    /// <c>AddAISentinel</c> so they can wire <c>AddSentinelSqliteApprovalStore</c> /
    /// <c>AddSentinelEntraPimApprovalStore</c> first — otherwise <c>AddAISentinel</c>
    /// auto-registers <see cref="InMemoryApprovalStore"/> and the backend extensions
    /// throw on duplicate registration.
    /// </summary>
    public static ApprovalBackendKind GetBackend(ApprovalConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return ParseBackend(config.Backend);
    }

    private static ApprovalBackendKind ParseBackend(string backend) =>
        backend.Trim().ToLowerInvariant() switch
        {
            "none" => ApprovalBackendKind.None,
            "in-memory" => ApprovalBackendKind.InMemory,
            "sqlite" => ApprovalBackendKind.Sqlite,
            "entra-pim" => ApprovalBackendKind.EntraPim,
            _ => throw new InvalidOperationException(
                $"Unknown backend '{backend}'. Loader should have caught this — fix Validate."),
        };
}
