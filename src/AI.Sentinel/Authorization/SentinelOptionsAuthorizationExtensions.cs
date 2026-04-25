namespace AI.Sentinel.Authorization;

/// <summary>Extension methods on <see cref="SentinelOptions"/> for tool-call authorization configuration.</summary>
public static class SentinelOptionsAuthorizationExtensions
{
    /// <summary>Binds a tool name (or wildcard pattern with <c>*</c> suffix) to a named <see cref="IAuthorizationPolicy"/>.</summary>
    /// <param name="opts">The Sentinel options to configure.</param>
    /// <param name="toolNameOrPattern">Exact tool name, or a wildcard pattern ending with <c>*</c>.</param>
    /// <param name="policyName">Name of a registered <see cref="IAuthorizationPolicy"/> (matches <see cref="AuthorizationPolicyAttribute.Name"/>).</param>
    /// <returns>The same <see cref="SentinelOptions"/> instance, to support fluent chaining.</returns>
    public static SentinelOptions RequireToolPolicy(this SentinelOptions opts, string toolNameOrPattern, string policyName)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolNameOrPattern);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        opts.AddAuthorizationBinding(new ToolCallPolicyBinding(toolNameOrPattern, policyName));
        return opts;
    }
}
