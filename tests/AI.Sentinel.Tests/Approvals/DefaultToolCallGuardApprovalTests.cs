using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AI.Sentinel.Tests.Approvals;

public class DefaultToolCallGuardApprovalTests
{
    private sealed record TestSec(string Id) : ISecurityContext
    {
#pragma warning disable HLQ001 // Boxing on init is fine for a test helper
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
#pragma warning restore HLQ001
    }

    private sealed class StubStore(ApprovalState fixedResult) : IApprovalStore
    {
        public ValueTask<ApprovalState> EnsureRequestAsync(ISecurityContext c, ApprovalSpec s, ApprovalContext ctx, CancellationToken t) =>
            ValueTask.FromResult(fixedResult);
        public ValueTask<ApprovalState> WaitForDecisionAsync(string id, TimeSpan to, CancellationToken t) =>
            ValueTask.FromResult(fixedResult);
    }

    private static DefaultToolCallGuard BuildGuard(IApprovalStore? approvalStore, params ToolCallPolicyBinding[] bindings) =>
        new(
            bindings: bindings,
            policiesByName: new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal),
            @default: ToolPolicyDefault.Allow,
            approvalStore: approvalStore,
            logger: NullLogger<DefaultToolCallGuard>.Instance);

    private static ApprovalSpec MakeSpec() => new() { PolicyName = "approval:delete_database" };

    [Fact]
    public async Task Authorize_ApprovalActive_ReturnsAllow()
    {
        var store = new StubStore(new ApprovalState.Active(DateTimeOffset.UtcNow.AddMinutes(15)));
        var guard = BuildGuard(store, new ToolCallPolicyBinding("delete_database", "approval:delete_database", MakeSpec()));

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "delete_database", default, default);

        Assert.IsType<AuthorizationDecision.AllowDecision>(d);
    }

    [Fact]
    public async Task Authorize_ApprovalPending_ReturnsRequireApproval()
    {
        var store = new StubStore(new ApprovalState.Pending("req-1", "https://example.test/approve/req-1", DateTimeOffset.UtcNow));
        var guard = BuildGuard(store, new ToolCallPolicyBinding("delete_database", "approval:delete_database", MakeSpec()));

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "delete_database", default, default);

        var r = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal("req-1", r.RequestId);
        Assert.Equal("approval:delete_database", r.PolicyName);
    }

    [Fact]
    public async Task Authorize_ApprovalDenied_ReturnsDeny()
    {
        var store = new StubStore(new ApprovalState.Denied("approver said no", DateTimeOffset.UtcNow));
        var guard = BuildGuard(store, new ToolCallPolicyBinding("delete_database", "approval:delete_database", MakeSpec()));

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "delete_database", default, default);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(d);
        Assert.Equal("approval:delete_database", deny.PolicyName);
        Assert.Contains("approver said no", deny.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Authorize_ApprovalSpecPresent_NoStore_Throws()
    {
        var guard = BuildGuard(approvalStore: null,
            new ToolCallPolicyBinding("delete_database", "approval:delete_database", MakeSpec()));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            guard.AuthorizeAsync(new TestSec("alice"), "delete_database", default, default).AsTask());
    }
}
