using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization.Policies;

public class AdminOnlyPolicyTests
{
    [Fact]
    public async Task AdminCaller_Allowed()
    {
        var p = new AdminOnlyPolicy();
        Assert.True((await p.EvaluateAsync(new TestSecurityContext("alice", "admin"), TestContext.Current.CancellationToken)).IsSuccess);
    }

    [Fact]
    public async Task NonAdminCaller_Denied()
    {
        var p = new AdminOnlyPolicy();
        var result = await p.EvaluateAsync(new TestSecurityContext("bob", "user"), TestContext.Current.CancellationToken);
        Assert.True(result.IsFailure);
        Assert.Equal(SentinelDenyCodes.PolicyDenied, result.Error.Code);
    }
}
