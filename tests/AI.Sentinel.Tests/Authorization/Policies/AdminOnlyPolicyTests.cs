using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization.Policies;

public class AdminOnlyPolicyTests
{
    [Fact]
    public void AdminCaller_Allowed()
    {
        var p = new AdminOnlyPolicy();
        Assert.True(p.IsAuthorized(new TestSecurityContext("alice", "admin")));
    }

    [Fact]
    public void NonAdminCaller_Denied()
    {
        var p = new AdminOnlyPolicy();
        Assert.False(p.IsAuthorized(new TestSecurityContext("bob", "user")));
    }
}
