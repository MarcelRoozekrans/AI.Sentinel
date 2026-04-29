using System.Text.Json;
using AI.Sentinel.Approvals;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Authorization;

/// <summary>Default tool-call guard. Resolves bindings → policies, fails closed on errors.</summary>
internal sealed class DefaultToolCallGuard(
    IReadOnlyList<ToolCallPolicyBinding> bindings,
    IReadOnlyDictionary<string, IAuthorizationPolicy> policiesByName,
    ToolPolicyDefault @default,
    IApprovalStore? approvalStore,
    ILogger<DefaultToolCallGuard>? logger) : IToolCallGuard
{
    private readonly ToolCallPolicyBinding[] _bindings = [.. bindings];

    public async ValueTask<AuthorizationDecision> AuthorizeAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        CancellationToken ct = default)
    {
        var matchCount = 0;
        foreach (var b in _bindings)
        {
            if (b.Matches(toolName)) matchCount++;
        }

        if (matchCount == 0)
        {
            return @default == ToolPolicyDefault.Allow
                ? AuthorizationDecision.Allow
                : AuthorizationDecision.Deny("default", "No matching policy and DefaultToolPolicy is Deny");
        }

        var ctx = new ToolCallContextWrapper(caller, toolName, args);

        foreach (var binding in _bindings)
        {
            if (!binding.Matches(toolName)) continue;

            var decision = binding.ApprovalSpec is { } approvalSpec
                ? await EvaluateApprovalAsync(caller, toolName, args, approvalSpec, ct).ConfigureAwait(false)
                : EvaluatePolicy(binding, ctx);

            if (decision is not null) return decision;
        }

        return AuthorizationDecision.Allow;
    }

    private async ValueTask<AuthorizationDecision?> EvaluateApprovalAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        ApprovalSpec approvalSpec,
        CancellationToken ct)
    {
        if (approvalStore is null)
        {
            throw new InvalidOperationException(
                "RequireApproval configured but no IApprovalStore registered. Add AddSentinelInMemoryApprovalStore() or one of the alternatives.");
        }

        var approvalCtx = new ApprovalContext(toolName, args, Justification: null);
        ApprovalState state;
        try
        {
            state = await approvalStore.EnsureRequestAsync(caller, approvalSpec, approvalCtx, ct).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Fail-closed: any approval-store exception must deny.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            logger?.LogError(ex, "IApprovalStore threw for policy '{PolicyName}' — failing closed (deny).", approvalSpec.PolicyName);
            return AuthorizationDecision.Deny(approvalSpec.PolicyName,
                $"Approval store threw {ex.GetType().Name}");
        }

        return state switch
        {
            ApprovalState.Active => null, // active grant — continue evaluating remaining bindings
            ApprovalState.Pending p => AuthorizationDecision.RequireApproval(
                approvalSpec.PolicyName, p.RequestId, p.ApprovalUrl, p.RequestedAt),
            ApprovalState.Denied d => AuthorizationDecision.Deny(approvalSpec.PolicyName, d.Reason),
            _ => AuthorizationDecision.Deny(approvalSpec.PolicyName, "unknown approval state"),
        };
    }

    private AuthorizationDecision? EvaluatePolicy(ToolCallPolicyBinding binding, ToolCallContextWrapper ctx)
    {
        if (!policiesByName.TryGetValue(binding.PolicyName, out var policy))
        {
            logger?.LogError("Policy '{PolicyName}' is bound to '{Pattern}' but not registered — denying.", binding.PolicyName, binding.Pattern);
            return AuthorizationDecision.Deny(binding.PolicyName,
                $"Policy '{binding.PolicyName}' is not registered");
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
            return AuthorizationDecision.Deny(binding.PolicyName,
                $"Policy threw {ex.GetType().Name}");
        }

        return allowed ? null : AuthorizationDecision.Deny(binding.PolicyName, "Policy denied");
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
