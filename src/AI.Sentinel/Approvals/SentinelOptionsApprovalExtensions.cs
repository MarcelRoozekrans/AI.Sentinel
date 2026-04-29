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

        var spec = new ApprovalSpec { PolicyName = $"approval:{toolPattern}" };
        configure(spec);

        opts.AddAuthorizationBinding(new ToolCallPolicyBinding(toolPattern, spec.PolicyName, spec));
        return opts;
    }
}
