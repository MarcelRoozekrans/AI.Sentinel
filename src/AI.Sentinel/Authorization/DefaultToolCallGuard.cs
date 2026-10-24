using System.Diagnostics;
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

    // Evaluation slots in registration order.
    private readonly Slot[] _slots = BuildSlots(bindings);

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
            if (!slot.Matches(toolName)) continue;

            var decision = slot switch
            {
                GroupSlot group => await EvaluateGroupAsync(caller, toolName, args, group, ct).ConfigureAwait(false),
                PolicySlot policy => await EvaluatePolicyAsync(policy.Binding, ctx, ct).ConfigureAwait(false),
                _ => throw new UnreachableException(),
            };

            if (decision is not null) return decision;
        }

        return AuthorizationDecision.Allow;
    }

    private static Slot[] BuildSlots(IReadOnlyList<ToolCallPolicyBinding> bindings)
    {
        var slots = new List<Slot>(bindings.Count);
        var groups = new Dictionary<string, GroupSlot>(StringComparer.Ordinal);
        foreach (var binding in bindings)
        {
            if (binding.ApprovalSpec is null)
            {
                slots.Add(new PolicySlot(binding));
                continue;
            }

            if (!groups.TryGetValue(binding.Pattern, out var group))
            {
                group = new GroupSlot(binding);
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
        GroupSlot group,
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
            spec = spec.WithPolicyName($"{spec.PolicyName}#{ArgumentFingerprint.Compute(args)}");

        return await EvaluateApprovalAsync(caller, toolName, args, spec, approvalStore, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Returns the spec of the first group member with no conditions, or whose conditions all
    /// hold. Fails closed: arguments that are not a JSON object or array satisfy every condition,
    /// and a condition that cannot be decided counts as holding.
    /// </summary>
    private ApprovalSpec? SelectSpec(GroupSlot group, JsonElement args)
    {
        var structured = args.ValueKind is JsonValueKind.Object or JsonValueKind.Array;
        foreach (var member in group.Members)
        {
            var spec = member.ApprovalSpec!;
            if (spec.Conditions.Count == 0 || !structured || ConditionsHold(spec, args))
                return spec;
        }

        return null;
    }

    private bool ConditionsHold(ApprovalSpec spec, JsonElement args)
    {
        List<string>? undecided = null;
        try
        {
            foreach (var condition in spec.Conditions)
            {
                var result = condition.Evaluate(args);
                if (result == ConditionResult.DoesNotHold)
                    return false;
                if (result != ConditionResult.Holds)
                    (undecided ??= []).Add($"{condition.Path.Text} ({Describe(result)})");
            }

            return true;
        }
#pragma warning disable CA1031 // Fail-closed: a condition that throws must select its rule, never skip it.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            logger?.LogError(ex, "Evaluating the conditions of approval rule '{PolicyName}' threw — counting the rule as matching (fail closed).", spec.PolicyName);
            return true;
        }
        finally
        {
            if (undecided is not null)
            {
                logger?.LogWarning(
                    "Approval rule '{PolicyName}': condition(s) {Conditions} could not be decided; counted as holding.",
                    spec.PolicyName, string.Join(", ", undecided));
            }
        }
    }

    private static string Describe(ConditionResult result) => result switch
    {
        ConditionResult.TimedOut => "timed out",
        ConditionResult.Unreadable => "unreadable string in arguments",
        ConditionResult.AmbiguousKey => "duplicate key in arguments",
        _ => result.ToString(),
    };

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

    /// <summary>One evaluation slot, in registration order.</summary>
    private abstract class Slot(ToolCallPolicyBinding first)
    {
        public bool Matches(string toolName) => first.Matches(toolName);
    }

    /// <summary>A policy binding, evaluated in its own slot.</summary>
    private sealed class PolicySlot(ToolCallPolicyBinding binding) : Slot(binding)
    {
        public ToolCallPolicyBinding Binding { get; } = binding;
    }

    /// <summary>Approval bindings sharing one pattern string, in registration order.</summary>
    private sealed class GroupSlot(ToolCallPolicyBinding first) : Slot(first)
    {
        public List<ToolCallPolicyBinding> Members { get; } = [];
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
