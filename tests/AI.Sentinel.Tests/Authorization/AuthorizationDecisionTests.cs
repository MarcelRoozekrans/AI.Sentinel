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
            requestedAt: DateTimeOffset.UtcNow,
            waitTimeout: TimeSpan.FromMinutes(5));

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
            "AdminApproval", "req-1", "url", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        var binary = pending.AsBinary();

        Assert.IsType<AuthorizationDecision.DenyDecision>(binary);
    }

    [Fact]
    public void Deny_WithoutCode_AppliesDefaultPolicyDeniedCode()
    {
        var deny = AuthorizationDecision.Deny("AdminOnly", "user is not admin");
        Assert.Equal("policy_denied", deny.Code);
    }

    [Fact]
    public void Deny_WithCode_PreservesPolicySuppliedCode()
    {
        var deny = AuthorizationDecision.Deny("TenantActive", "tenant evicted", "tenant_inactive");
        Assert.Equal("tenant_inactive", deny.Code);
        Assert.Equal("TenantActive", deny.PolicyName);
        Assert.Equal("tenant evicted", deny.Reason);
    }
}
