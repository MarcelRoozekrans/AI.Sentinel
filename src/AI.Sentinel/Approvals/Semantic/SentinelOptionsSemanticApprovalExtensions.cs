namespace AI.Sentinel.Approvals.Semantic;

/// <summary>Extensions for gating tool calls on how close their text is in meaning to example calls.</summary>
public static class SentinelOptionsSemanticApprovalExtensions
{
    /// <summary>Binds <paramref name="toolPattern"/> to a semantic approval gate.</summary>
    /// <param name="opts">The Sentinel options to configure.</param>
    /// <param name="toolPattern">Exact tool name or wildcard pattern ending with <c>*</c>.</param>
    /// <param name="configure">Semantic approval configuration; must set <see cref="SemanticApprovalSpec.BackendBinding"/>.</param>
    /// <returns>The same <see cref="SentinelOptions"/> for fluent chaining.</returns>
    /// <exception cref="InvalidOperationException">The pattern is already registered, the backend binding is
    /// missing, or the threshold is outside (0, 1].</exception>
    public static SentinelOptions RequireSemanticApproval(
        this SentinelOptions opts, string toolPattern, Action<SemanticApprovalSpec> configure)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolPattern);
        ArgumentNullException.ThrowIfNull(configure);

        if (opts.GetSemanticApprovals().Tools.Any(t => string.Equals(t.Pattern, toolPattern, StringComparison.Ordinal)))
            throw new InvalidOperationException(
                $"Semantic approval for '{toolPattern}' is already registered. Each tool pattern can be registered once.");

        var spec = new SemanticApprovalSpec();
        configure(spec);

        if (string.IsNullOrWhiteSpace(spec.BackendBinding))
            throw new InvalidOperationException(
                $"Semantic approval for '{toolPattern}' needs a BackendBinding.");
        if (spec.Threshold is { } t && !(t > 0f && t <= 1f))
            throw new InvalidOperationException(
                $"Semantic approval for '{toolPattern}' has threshold {t}; it must be above 0 and at most 1.");

        opts.AddSemanticApproval(toolPattern, spec);
        return opts;
    }

    /// <summary>Configures the settings shared by every semantic approval binding.</summary>
    /// <param name="opts">The Sentinel options to configure.</param>
    /// <param name="configure">Settings configuration.</param>
    /// <returns>The same <see cref="SentinelOptions"/> for fluent chaining.</returns>
    /// <exception cref="InvalidOperationException">The threshold is outside (0, 1].</exception>
    public static SentinelOptions ConfigureSemanticApprovals(
        this SentinelOptions opts, Action<SemanticApprovalSettings> configure)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(configure);
        var settings = opts.GetSemanticApprovals().Settings;
        configure(settings);
        if (settings.Threshold is { } t && !(t > 0f && t <= 1f))
            throw new InvalidOperationException(
                $"Semantic approval settings have threshold {t}; it must be above 0 and at most 1.");
        return opts;
    }
}
