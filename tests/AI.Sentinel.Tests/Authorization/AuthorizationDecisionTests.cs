using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class AuthorizationDecisionTests
{
    [Fact]
    public void RequireApproval_Allowed_IsFalse()
    {
        var d = AuthorizationDecision.RequireApproval(
            policyName: "AdminApproval",
            requestId: "req-123",
            approvalUrl: "https://example.test/approve/req-123",
            requestedAt: DateTimeOffset.UtcNow);

        Assert.False(d.Allowed);
        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
    }

    [Fact]
    public void Allow_Allowed_IsTrue() =>
        Assert.True(AuthorizationDecision.Allow.Allowed);

    [Fact]
    public void Deny_Allowed_IsFalse() =>
        Assert.False(AuthorizationDecision.Deny("p", "r").Allowed);

    [Fact]
    public void AsBinary_RequireApproval_BecomesDeny()
    {
        var pending = AuthorizationDecision.RequireApproval(
            "AdminApproval", "req-1", "url", DateTimeOffset.UtcNow);

        var binary = pending.AsBinary();

        Assert.IsType<AuthorizationDecision.DenyDecision>(binary);
    }
}
