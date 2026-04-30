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
    /// <see cref="ApprovalConfig.Tools"/>, then returns the backend kind the config selected.
    /// </summary>
    public static ApprovalBackendKind Configure(SentinelOptions opts, ApprovalConfig config)
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
