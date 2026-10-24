using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Extension for opting a tool (or wildcard pattern) into an approval gate. The caller
/// must obtain out-of-band approval from the configured <see cref="IApprovalStore"/>
/// before the tool call is allowed. Stack with <see cref="SentinelOptionsAuthorizationExtensions.RequireToolPolicy"/>
/// for stricter eligibility (eligibility check first, then approval gate).
/// </summary>
public static class SentinelOptionsApprovalExtensions
{
    /// <summary>Binds <paramref name="toolPattern"/> to an approval gate.</summary>
    /// <param name="opts">The Sentinel options to configure.</param>
    /// <param name="toolPattern">Exact tool name or wildcard pattern ending with <c>*</c>.</param>
    /// <param name="configure">Approval-spec configuration (policy name, grant duration, etc.).</param>
    /// <returns>The same <see cref="SentinelOptions"/> for fluent chaining.</returns>
    public static SentinelOptions RequireApproval(
        this SentinelOptions opts, string toolPattern, Action<ApprovalSpec> configure)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolPattern);
        ArgumentNullException.ThrowIfNull(configure);

        var defaultName = $"approval:{toolPattern}";
        var bindings = opts.GetAuthorizationBindings();
        var existing = bindings.Count(b =>
            b.ApprovalSpec is not null && string.Equals(b.Pattern, toolPattern, StringComparison.Ordinal));

        var spec = new ApprovalSpec { PolicyName = defaultName };
        configure(spec);
        if (existing > 0 && string.Equals(spec.PolicyName, defaultName, StringComparison.Ordinal))
            spec.PolicyName = $"{defaultName}[{existing}]";

        if (bindings.Any(b =>
                b.ApprovalSpec is not null && string.Equals(b.ApprovalSpec.PolicyName, spec.PolicyName, StringComparison.Ordinal)))
            throw new InvalidOperationException(
                $"Approval policy name '{spec.PolicyName}' is already in use. Approval policy names must be unique.");

        opts.AddAuthorizationBinding(new ToolCallPolicyBinding(toolPattern, spec.PolicyName, spec));
        return opts;
    }
}
