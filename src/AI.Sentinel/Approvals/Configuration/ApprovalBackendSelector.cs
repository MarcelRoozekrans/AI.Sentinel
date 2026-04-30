using AI.Sentinel.Approvals;

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
public static class ApprovalBackendSelector
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

        foreach (var (toolPattern, toolConfig) in config.Tools)
        {
            var grantMinutes = toolConfig.GrantMinutes ?? config.DefaultGrantMinutes;
            var requireJustification = toolConfig.RequireJustification ?? true;

            opts.RequireApproval(toolPattern, spec =>
            {
                spec.GrantDuration = TimeSpan.FromMinutes(grantMinutes);
                spec.RequireJustification = requireJustification;
                spec.BackendBinding = toolConfig.Role;
            });
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
            "none"      => ApprovalBackendKind.None,
            "in-memory" => ApprovalBackendKind.InMemory,
            "sqlite"    => ApprovalBackendKind.Sqlite,
            "entra-pim" => ApprovalBackendKind.EntraPim,
            _           => throw new InvalidOperationException(
                $"Unknown backend '{backend}'. Loader should have caught this — fix Validate."),
        };
}
