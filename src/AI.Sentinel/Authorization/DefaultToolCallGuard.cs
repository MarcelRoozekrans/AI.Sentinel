using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Conditions;
using Microsoft.Extensions.Logging;
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Authorization;

/// <summary>Default tool-call guard. Resolves bindings → policies, fails closed on errors.</summary>
/// <remarks>
/// Approval bindings that share the exact same pattern string form a group, evaluated in the
/// registration slot of its first member. Within a group only the first binding whose argument
/// conditions all hold, or that has none, is evaluated. Policy bindings are never grouped.
/// </remarks>
internal sealed class DefaultToolCallGuard(
    IReadOnlyList<ToolCallPolicyBinding> bindings,
    IReadOnlyDictionary<string, IAuthorizationPolicy> policiesByName,
    ToolPolicyDefault @default,
    IApprovalStore? approvalStore,
    ILogger<DefaultToolCallGuard>? logger) : IToolCallGuard
{
    private readonly ToolCallPolicyBinding[] _bindings = [.. bindings];

    // Evaluation slots in registration order: each a policy binding or an ApprovalGroup.
    private readonly object[] _slots = BuildSlots(bindings);

    public async ValueTask<AuthorizationDecision> AuthorizeAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        CancellationToken ct = default)
    {
        // Governed or not is decided on the tool name alone: a matching approval rule whose
        // conditions do not hold still keeps DefaultToolPolicy from applying.
        var governed = false;
        foreach (var b in _bindings)
        {
            if (b.Matches(toolName))
            {
                governed = true;
                break;
            }
        }

        if (!governed)
        {
            return @default == ToolPolicyDefault.Allow
                ? AuthorizationDecision.Allow
                : AuthorizationDecision.Deny("default", "No matching policy and DefaultToolPolicy is Deny");
        }

        var ctx = new ToolCallContextWrapper(caller, toolName, args);

        foreach (var slot in _slots)
        {
            AuthorizationDecision? decision;
            if (slot is ApprovalGroup group)
            {
                if (!group.Matches(toolName)) continue;
                decision = await EvaluateGroupAsync(caller, toolName, args, group, ct).ConfigureAwait(false);
            }
            else
            {
                var binding = (ToolCallPolicyBinding)slot;
                if (!binding.Matches(toolName)) continue;
                decision = await EvaluatePolicyAsync(binding, ctx, ct).ConfigureAwait(false);
            }

            if (decision is not null) return decision;
        }

        return AuthorizationDecision.Allow;
    }

    private static object[] BuildSlots(IReadOnlyList<ToolCallPolicyBinding> bindings)
    {
        var slots = new List<object>(bindings.Count);
        var groups = new Dictionary<string, ApprovalGroup>(StringComparer.Ordinal);
        foreach (var binding in bindings)
        {
            if (binding.ApprovalSpec is null)
            {
                slots.Add(binding);
                continue;
            }

            if (!groups.TryGetValue(binding.Pattern, out var group))
            {
                group = new ApprovalGroup(binding);
                groups.Add(binding.Pattern, group);
                slots.Add(group);
            }

            group.Members.Add(binding);
        }

        return [.. slots];
    }

    private async ValueTask<AuthorizationDecision?> EvaluateGroupAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        ApprovalGroup group,
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

        var spec = SelectSpec(group, args);
        if (spec is null) return null; // no rule of the group applies to these arguments

        if (spec.GrantScope == ApprovalGrantScope.Call)
        {
            spec = new ApprovalSpec
            {
                PolicyName = $"{spec.PolicyName}#{ArgumentFingerprint.Compute(args)}",
                GrantDuration = spec.GrantDuration,
                RequireJustification = spec.RequireJustification,
                WaitTimeout = spec.WaitTimeout,
                BackendBinding = spec.BackendBinding,
                GrantScope = spec.GrantScope,
            };
        }

        return await EvaluateApprovalAsync(caller, toolName, args, spec, approvalStore, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Returns the spec of the first group member with no conditions, or whose conditions all
    /// hold. Fails closed: a timed-out condition holds, and arguments that are not a JSON object
    /// or array satisfy every condition.
    /// </summary>
    private ApprovalSpec? SelectSpec(ApprovalGroup group, JsonElement args)
    {
        var structured = args.ValueKind is JsonValueKind.Object or JsonValueKind.Array;
        foreach (var member in group.Members)
        {
            var spec = member.ApprovalSpec!;
            if (spec.Conditions.Count == 0 || !structured) return spec;

            var holds = true;
            List<string>? timedOutPaths = null;
            foreach (var condition in spec.Conditions)
            {
                var result = condition.Evaluate(args);
                if (result == ConditionResult.DoesNotHold)
                {
                    holds = false;
                    break;
                }

                if (result == ConditionResult.TimedOut)
                    (timedOutPaths ??= []).Add(condition.Path.Text);
            }

            if (timedOutPaths is not null)
            {
                logger?.LogWarning(
                    "Approval rule '{PolicyName}' timed out matching argument path(s) {Paths} — treating the condition as holding (fail closed).",
                    spec.PolicyName, string.Join(", ", timedOutPaths));
            }

            if (holds) return spec;
        }

        return null;
    }

    private async ValueTask<AuthorizationDecision?> EvaluateApprovalAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        ApprovalSpec approvalSpec,
        IApprovalStore store,
        CancellationToken ct)
    {
        var approvalCtx = new ApprovalContext(toolName, args, Justification: null);
        ApprovalState state;
        try
        {
            state = await store.EnsureRequestAsync(caller, approvalSpec, approvalCtx, ct).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Fail-closed: any approval-store exception must deny.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            logger?.LogError(ex, "IApprovalStore threw for policy '{PolicyName}' — failing closed (deny).", approvalSpec.PolicyName);
            return AuthorizationDecision.Deny(approvalSpec.PolicyName,
                $"Approval store threw {ex.GetType().Name}",
                SentinelDenyCodes.ApprovalStoreException);
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
                SentinelDenyCodes.ApprovalStateUnknown),
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
                SentinelDenyCodes.PolicyNotRegistered);
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
                SentinelDenyCodes.PolicyException);
        }

        if (result.IsSuccess)
        {
            return null;   // allow — policy evaluation passed
        }

        var failure = result.Error;
        // A policy that denies without picking a code emits ZeroAlloc.Authorization's
        // AuthorizationFailure.DefaultDenyCode (= "policy.deny"), and may leave Reason null.
        // AI.Sentinel canonicalises both to its stable wire format (code='policy_denied' /
        // reason='Policy denied') so Phase 2/3/4 surfaces (audit, hook receipts, MCP error body,
        // dashboard) assert against the same shape regardless of how much detail the policy
        // author supplied.
        var code = string.Equals(failure.Code, AuthorizationFailure.DefaultDenyCode, StringComparison.Ordinal)
            ? SentinelDenyCodes.PolicyDenied
            : failure.Code;
        var reason = failure.Reason ?? "Policy denied";
        return AuthorizationDecision.Deny(binding.PolicyName, reason, code);
    }

    /// <summary>Approval bindings sharing one pattern string, in registration order.</summary>
    private sealed class ApprovalGroup(ToolCallPolicyBinding first)
    {
        public List<ToolCallPolicyBinding> Members { get; } = [];

        public bool Matches(string toolName) => first.Matches(toolName);
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
