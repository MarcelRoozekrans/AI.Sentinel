using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using AI.Sentinel.Tests.Helpers;
using Xunit;
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Tests.Authorization;

public class DefaultToolCallGuardTests
{
    private static readonly JsonElement EmptyArgs = JsonDocument.Parse("{}").RootElement;

    [Policy("test-admin-only")]
    internal sealed class AdminOnly : IAuthorizationPolicy
    {
        public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            ISecurityContext ctx, CancellationToken ct = default) =>
            new(ctx.Roles.Contains("admin")
                ? UnitResult<AuthorizationFailure>.Success()
                : UnitResult<AuthorizationFailure>.Failure(
                    new AuthorizationFailure(AuthorizationFailure.DefaultDenyCode, null!)));
    }

    [Policy("always-deny")]
    // Denies without picking a code or reason — the shape the guard has to canonicalise
    // to code='policy_denied' / reason='Policy denied'.
    internal sealed class AlwaysDeny : IAuthorizationPolicy
    {
        public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            ISecurityContext ctx, CancellationToken ct = default) =>
            new(UnitResult<AuthorizationFailure>.Failure(
                new AuthorizationFailure(AuthorizationFailure.DefaultDenyCode, null!)));
    }

    [Policy("throws")]
    internal sealed class Throws : IAuthorizationPolicy
    {
        public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            ISecurityContext ctx, CancellationToken ct = default) =>
            throw new InvalidOperationException("boom");
    }

    private static DefaultToolCallGuard Build(
        ToolPolicyDefault @default,
        IEnumerable<(string pattern, string policyName)>? bindings = null,
        IEnumerable<IAuthorizationPolicy>? policies = null)
    {
        bindings ??= [];
        policies ??= [];
        var policyByName = policies
            .Select(p => (Name: p.GetType().GetCustomAttributes(typeof(PolicyAttribute), false)
                .Cast<PolicyAttribute>().Single().Name, Policy: p))
            .ToDictionary(t => t.Name, t => t.Policy, StringComparer.Ordinal);
        return new DefaultToolCallGuard(
            bindings.Select(b => new ToolCallPolicyBinding(b.pattern, b.policyName)).ToList(),
            policyByName,
            @default,
            approvalStore: null,
            logger: null);
    }

    [Fact]
    public async Task NoPoliciesRegistered_AllowsByDefault()
    {
        var guard = Build(ToolPolicyDefault.Allow);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "anything", EmptyArgs);
        Assert.True(d.Allowed);
    }

    [Fact]
    public async Task ExactToolMatch_UsesBoundPolicy_AllowedForAdmin()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "test-admin-only")],
            policies: [new AdminOnly()]);
        var caller = new TestSecurityContext("alice", "admin");
        var d = await guard.AuthorizeAsync(caller, "Bash", EmptyArgs);
        Assert.True(d.Allowed);
    }

    [Fact]
    public async Task ExactToolMatch_UsesBoundPolicy_DeniedForNonAdmin()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "test-admin-only")],
            policies: [new AdminOnly()]);
        var caller = new TestSecurityContext("bob");
        var d = await guard.AuthorizeAsync(caller, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
        Assert.Equal("test-admin-only", Assert.IsType<AuthorizationDecision.DenyDecision>(d).PolicyName);
    }

    [Fact]
    public async Task WildcardMatch_DeleteUnderscoreStarMatchesDeleteUser()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("delete_*", "test-admin-only")],
            policies: [new AdminOnly()]);
        var caller = new TestSecurityContext("bob");
        var d = await guard.AuthorizeAsync(caller, "delete_user", EmptyArgs);
        Assert.False(d.Allowed);
    }

    [Fact]
    public async Task MultipleMatchingPolicies_AllMustAllow()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "test-admin-only"), ("*", "always-deny")],
            policies: [new AdminOnly(), new AlwaysDeny()]);
        var caller = new TestSecurityContext("alice", "admin");
        var d = await guard.AuthorizeAsync(caller, "Bash", EmptyArgs);
        Assert.False(d.Allowed); // always-deny blocks even though admin-only allows
        Assert.Equal("always-deny", Assert.IsType<AuthorizationDecision.DenyDecision>(d).PolicyName);
    }

    [Fact]
    public async Task NoMatch_UsesDefaultToolPolicy_Allow()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "test-admin-only")],
            policies: [new AdminOnly()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Read", EmptyArgs);
        Assert.True(d.Allowed);
    }

    [Fact]
    public async Task NoMatch_UsesDefaultToolPolicy_Deny()
    {
        var guard = Build(ToolPolicyDefault.Deny,
            bindings: [("Bash", "test-admin-only")],
            policies: [new AdminOnly()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Read", EmptyArgs);
        Assert.False(d.Allowed);
    }

    [Fact]
    public async Task PolicyThrows_FailsClosed_ReturnsDeny()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "throws")],
            policies: [new Throws()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(d);
        Assert.Equal("throws", deny.PolicyName);
        Assert.Equal("policy_exception", deny.Code);
    }

    [Fact]
    public async Task BindingReferencesUnknownPolicy_ReturnsDeny()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "ghost-policy")],
            policies: []);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
        Assert.Equal("ghost-policy", Assert.IsType<AuthorizationDecision.DenyDecision>(d).PolicyName);
    }

    [Fact]
    public async Task AnonymousCaller_PolicyReferencingRoles_Denies()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "test-admin-only")],
            policies: [new AdminOnly()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
    }

    [Policy("test-no-system-paths")]
    internal sealed class NoSystemPaths : ToolCallAuthorizationPolicy
    {
        protected override ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            IToolCallSecurityContext ctx, CancellationToken ct)
        {
            if (!string.Equals(ctx.ToolName, "Bash", StringComparison.Ordinal)) return new(Allow());
            if (!ctx.Args.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String) return new(Allow());
            var path = p.GetString();
            return new(path is null || (!path.StartsWith("/etc/", StringComparison.Ordinal)
                                      && !path.StartsWith("/sys/", StringComparison.Ordinal))
                ? Allow()
                : Deny($"Bash 'path' argument '{path}' targets a protected system directory"));
        }
    }

    [Fact]
    public async Task ToolCallContext_PolicyAccessesArgs()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "test-no-system-paths")],
            policies: [new NoSystemPaths()]);
        var caller = AnonymousSecurityContext.Instance;
        var bad   = JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement;
        var good  = JsonDocument.Parse("""{"path":"/tmp/foo"}""").RootElement;
        Assert.False((await guard.AuthorizeAsync(caller, "Bash", bad)).Allowed);
        Assert.True((await guard.AuthorizeAsync(caller, "Bash", good)).Allowed);
    }

    [Policy("tenant-active")]
    internal sealed class StructuredFailurePolicy : IAuthorizationPolicy
    {
        public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            ISecurityContext ctx, CancellationToken ct = default) =>
            new(UnitResult<AuthorizationFailure>.Failure(
                new AuthorizationFailure("tenant_inactive", "Tenant is in evicted state")));
    }

    [Policy("slow")]
    internal sealed class CancellationAwarePolicy : IAuthorizationPolicy
    {
        public async ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            ISecurityContext ctx, CancellationToken ct = default)
        {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            return UnitResult<AuthorizationFailure>.Success();
        }
    }

    [Fact]
    public async Task EvaluatePolicy_StructuredFailure_PropagatesCodeAndReasonToDecision()
    {
        var guard = Build(ToolPolicyDefault.Deny,
            bindings: [("Bash", "tenant-active")],
            policies: [new StructuredFailurePolicy()]);

        var decision = await guard.AuthorizeAsync(
            new TestSecurityContext("user-1"), "Bash", EmptyArgs);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
        Assert.Equal("tenant_inactive", deny.Code);
        Assert.Equal("Tenant is in evicted state", deny.Reason);
        Assert.Equal("tenant-active", deny.PolicyName);
    }

    [Fact]
    public async Task EvaluatePolicy_BareDenyPolicy_AppliesDefaultPolicyDeniedCode()
    {
        // AlwaysDeny denies with DefaultDenyCode and a null reason — the guard canonicalises
        // both to AuthorizationDecision's stable wire format ('policy_denied' / 'Policy denied').
        var guard = Build(ToolPolicyDefault.Deny,
            bindings: [("Bash", "always-deny")],
            policies: [new AlwaysDeny()]);

        var decision = await guard.AuthorizeAsync(
            new TestSecurityContext("user-1"), "Bash", EmptyArgs);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
        Assert.Equal("policy_denied", deny.Code);
        Assert.Equal("Policy denied", deny.Reason);
    }

    [Fact]
    public async Task EvaluatePolicy_CancellationToken_PropagatesToPolicy()
    {
        var guard = Build(ToolPolicyDefault.Deny,
            bindings: [("Bash", "slow")],
            policies: [new CancellationAwarePolicy()]);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await guard.AuthorizeAsync(
                new TestSecurityContext("user-1"), "Bash", EmptyArgs, cts.Token));
    }

    [Fact]
    public async Task EvaluatePolicy_CancellationToken_CancelledMidAwait_Propagates()
    {
        var guard = Build(ToolPolicyDefault.Deny,
            bindings: [("Bash", "slow")],
            policies: [new CancellationAwarePolicy()]);

        using var cts = new CancellationTokenSource();
        var task = guard.AuthorizeAsync(
            new TestSecurityContext("user-1"), "Bash", EmptyArgs, cts.Token).AsTask();
        cts.CancelAfter(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }

    private sealed class FakeApprovalStore : IApprovalStore
    {
        private readonly ApprovalState? _state;
        private readonly Exception? _ex;

        public FakeApprovalStore(ApprovalState state) { _state = state; }
        public FakeApprovalStore(Exception ex) { _ex = ex; }

        public ValueTask<ApprovalState> EnsureRequestAsync(
            ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
        {
            if (_ex is not null) throw _ex;
            return new ValueTask<ApprovalState>(_state!);
        }

        public ValueTask<ApprovalState> WaitForDecisionAsync(
            string requestId, TimeSpan timeout, CancellationToken ct) =>
            throw new NotSupportedException("not used in this test");
    }

    private static DefaultToolCallGuard BuildWithApproval(
        IApprovalStore approvalStore,
        ApprovalSpec spec)
    {
        var binding = new ToolCallPolicyBinding("Bash", spec.PolicyName, spec);
        return new DefaultToolCallGuard(
            [binding],
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal),
            ToolPolicyDefault.Deny,
            approvalStore: approvalStore,
            logger: null);
    }

    [Fact]
    public async Task EvaluateApproval_StoreThrows_DeniesWithApprovalStoreExceptionCode()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:Bash" };
        var store = new FakeApprovalStore(new InvalidOperationException("backend down"));
        var guard = BuildWithApproval(store, spec);

        var decision = await guard.AuthorizeAsync(
            new TestSecurityContext("user-1"), "Bash", EmptyArgs);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
        Assert.Equal("approval:Bash", deny.PolicyName);
        Assert.Equal("approval_store_exception", deny.Code);
    }

    [Fact]
    public async Task EvaluateApproval_DeniedState_KeepsPolicyDeniedCode()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:Bash" };
        var store = new FakeApprovalStore(new ApprovalState.Denied("approver said no", DateTimeOffset.UtcNow));
        var guard = BuildWithApproval(store, spec);

        var decision = await guard.AuthorizeAsync(
            new TestSecurityContext("user-1"), "Bash", EmptyArgs);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
        Assert.Equal("approval:Bash", deny.PolicyName);
        Assert.Equal("policy_denied", deny.Code);
        Assert.Equal("approver said no", deny.Reason);
    }

    private sealed class UnknownStateApprovalStore : IApprovalStore
    {
        // A custom (non-Active/Pending/Denied) ApprovalState subclass to exercise the default switch arm.
        private sealed record Mystery() : ApprovalState;

        public ValueTask<ApprovalState> EnsureRequestAsync(
            ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct) =>
            new(new Mystery());

        public ValueTask<ApprovalState> WaitForDecisionAsync(
            string requestId, TimeSpan timeout, CancellationToken ct) =>
            throw new NotSupportedException("not used in this test");
    }

    [Fact]
    public async Task EvaluateApproval_UnknownState_DeniesWithApprovalStateUnknownCode()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:Bash" };
        var guard = BuildWithApproval(new UnknownStateApprovalStore(), spec);

        var decision = await guard.AuthorizeAsync(
            new TestSecurityContext("user-1"), "Bash", EmptyArgs);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
        Assert.Equal("approval:Bash", deny.PolicyName);
        Assert.Equal("approval_state_unknown", deny.Code);
    }
}
