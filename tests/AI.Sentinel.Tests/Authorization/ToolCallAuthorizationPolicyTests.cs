using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Tests.Helpers;
using Xunit;
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Tests.Authorization;

public class ToolCallAuthorizationPolicyTests
{
    private sealed class DenyBashPolicy : ToolCallAuthorizationPolicy
    {
        protected override ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            IToolCallSecurityContext ctx, CancellationToken ct) =>
            new(!string.Equals(ctx.ToolName, "Bash", StringComparison.Ordinal)
                ? Allow()
                : Deny("Bash is not permitted"));
    }

    [Fact]
    public async Task NonToolCallContext_AlwaysAllowed()
    {
        var policy = new DenyBashPolicy();
        var caller = new TestSecurityContext("user");
        Assert.True((await policy.EvaluateAsync(caller)).IsSuccess);
    }

    [Fact]
    public async Task ToolCallContext_PolicyAppliesNormally()
    {
        var policy = new DenyBashPolicy();
        var inner  = new TestSecurityContext("user");
        var args   = JsonDocument.Parse("{}").RootElement;
        var bash   = new TestToolCallSecurityContext(inner, "Bash", args);
        var read   = new TestToolCallSecurityContext(inner, "Read", args);
        Assert.True((await policy.EvaluateAsync(bash)).IsFailure);
        Assert.True((await policy.EvaluateAsync(read)).IsSuccess);
    }
}
