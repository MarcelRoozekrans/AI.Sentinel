using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Authorization;

/// <summary>Default tool-call guard. Resolves bindings → policies, fails closed on errors.</summary>
internal sealed class DefaultToolCallGuard(
    IReadOnlyList<ToolCallPolicyBinding> bindings,
    IReadOnlyDictionary<string, IAuthorizationPolicy> policiesByName,
    ToolPolicyDefault @default,
    ILogger<DefaultToolCallGuard>? logger) : IToolCallGuard
{
    private readonly ToolCallPolicyBinding[] _bindings = [.. bindings];

    public ValueTask<AuthorizationDecision> AuthorizeAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        CancellationToken ct = default)
    {
        var bindingsSpan = _bindings.AsSpan();
        int matchCount = 0;
        foreach (ref readonly var b in bindingsSpan)
        {
            if (b.Matches(toolName)) matchCount++;
        }

        if (matchCount == 0)
        {
            return ValueTask.FromResult(@default == ToolPolicyDefault.Allow
                ? AuthorizationDecision.Allow
                : AuthorizationDecision.Deny("default", "No matching policy and DefaultToolPolicy is Deny"));
        }

        var ctx = new ToolCallContextWrapper(caller, toolName, args);

        foreach (ref readonly var binding in bindingsSpan)
        {
            if (!binding.Matches(toolName)) continue;
            if (!policiesByName.TryGetValue(binding.PolicyName, out var policy))
            {
                logger?.LogError("Policy '{PolicyName}' is bound to '{Pattern}' but not registered — denying.", binding.PolicyName, binding.Pattern);
                return ValueTask.FromResult(AuthorizationDecision.Deny(binding.PolicyName,
                    $"Policy '{binding.PolicyName}' is not registered"));
            }

            bool allowed;
            try
            {
                allowed = policy.IsAuthorized(ctx);
            }
#pragma warning disable CA1031 // Fail-closed: any policy exception must deny, regardless of type.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                logger?.LogError(ex, "Policy '{PolicyName}' threw — failing closed (deny).", binding.PolicyName);
                return ValueTask.FromResult(AuthorizationDecision.Deny(binding.PolicyName,
                    $"Policy threw {ex.GetType().Name}"));
            }

            if (!allowed)
            {
                return ValueTask.FromResult(AuthorizationDecision.Deny(binding.PolicyName,
                    "Policy denied"));
            }
        }

        return ValueTask.FromResult(AuthorizationDecision.Allow);
    }

    private sealed class ToolCallContextWrapper(ISecurityContext inner, string toolName, JsonElement args)
        : IToolCallSecurityContext
    {
        public string Id => inner.Id;
        public IReadOnlySet<string> Roles => inner.Roles;
        public IReadOnlyDictionary<string, string> Claims => inner.Claims;
        public string ToolName { get; } = toolName;
        public JsonElement Args { get; } = args;
    }
}
