using System.Text.Json;
using AI.Sentinel.Approvals;
using Microsoft.Extensions.Logging;
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

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
                : await EvaluatePolicyAsync(binding, ctx, ct).ConfigureAwait(false);

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
                "RequireApproval configured but no IApprovalStore registered. The InMemory store is auto-registered " +
                "by AddAISentinel when bindings carry an ApprovalSpec; if you cleared it explicitly, register one of " +
                "AddSentinelSqliteApprovalStore / AddSentinelEntraPimApprovalStore, or " +
                "services.AddSingleton<IApprovalStore, InMemoryApprovalStore>().");
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
                $"Approval store threw {ex.GetType().Name}",
                "approval_store_exception");
        }

        return state switch
        {
            ApprovalState.Active => null, // active grant — continue evaluating remaining bindings
            ApprovalState.Pending p => AuthorizationDecision.RequireApproval(
                approvalSpec.PolicyName, p.RequestId, p.ApprovalUrl, p.RequestedAt, approvalSpec.WaitTimeout),
            // Denied = real denial-by-approver: keep the default 'policy_denied' code so it lines up
            // with structured-policy denials. Operators differentiate via reason text.
            ApprovalState.Denied d => AuthorizationDecision.Deny(approvalSpec.PolicyName, d.Reason),
            _ => AuthorizationDecision.Deny(approvalSpec.PolicyName, "unknown approval state",
                "approval_state_unknown"),
        };
    }

    private async ValueTask<AuthorizationDecision?> EvaluatePolicyAsync(
        ToolCallPolicyBinding binding, ToolCallContextWrapper ctx, CancellationToken ct)
    {
        if (!policiesByName.TryGetValue(binding.PolicyName, out var policy))
        {
            logger?.LogError("Policy '{PolicyName}' is bound to '{Pattern}' but not registered — denying.", binding.PolicyName, binding.Pattern);
            return AuthorizationDecision.Deny(binding.PolicyName,
                $"Policy '{binding.PolicyName}' is not registered",
                "policy_not_registered");
        }

        UnitResult<AuthorizationFailure> result;
        try
        {
            result = await policy.EvaluateAsync(ctx, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Cooperative cancellation propagates — never silently denied.
            throw;
        }
#pragma warning disable CA1031 // Fail-closed: any other policy exception must deny, regardless of type.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            logger?.LogError(ex, "Policy '{PolicyName}' threw — failing closed (deny).", binding.PolicyName);
            return AuthorizationDecision.Deny(binding.PolicyName,
                $"Policy threw {ex.GetType().Name}",
                "policy_exception");
        }

        if (result.IsSuccess)
        {
            return null;   // allow — policy evaluation passed
        }

        var failure = result.Error;
        // ZeroAlloc.Authorization 1.1.0 IAuthorizationPolicy.EvaluateAsync DIM bridge: when
        // a sync-only policy returns IsAuthorized=false, the bridge produces
        //   new AuthorizationFailure(AuthorizationFailure.DefaultDenyCode /* = "policy.deny" */)
        // with Reason=null. AI.Sentinel canonicalises both to its stable wire format
        // (code='policy_denied' / reason='Policy denied') so Phase 2/3/4 surfaces (audit,
        // hook receipts, MCP error body, dashboard) assert against the same shape
        // regardless of whether the policy author opted into the structured Evaluate API.
        var code = string.Equals(failure.Code, AuthorizationFailure.DefaultDenyCode, StringComparison.Ordinal)
            ? "policy_denied"
            : failure.Code;
        var reason = failure.Reason ?? "Policy denied";
        return AuthorizationDecision.Deny(binding.PolicyName, reason, code);
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
