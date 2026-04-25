using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class ToolCallAuthorizationPolicyTests
{
    private sealed class DenyBashPolicy : ToolCallAuthorizationPolicy
    {
        protected override bool IsAuthorized(IToolCallSecurityContext ctx) =>
            !string.Equals(ctx.ToolName, "Bash", StringComparison.Ordinal);
    }

    [Fact]
    public void NonToolCallContext_AlwaysAllowed()
    {
        var policy = new DenyBashPolicy();
        var caller = new TestSecurityContext("user");
        Assert.True(policy.IsAuthorized(caller));
    }

    [Fact]
    public void ToolCallContext_PolicyAppliesNormally()
    {
        var policy = new DenyBashPolicy();
        var inner  = new TestSecurityContext("user");
        var args   = JsonDocument.Parse("{}").RootElement;
        var bash   = new TestToolCallSecurityContext(inner, "Bash", args);
        var read   = new TestToolCallSecurityContext(inner, "Read", args);
        Assert.False(policy.IsAuthorized(bash));
        Assert.True(policy.IsAuthorized(read));
    }
}
