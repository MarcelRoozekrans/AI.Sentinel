using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class SentinelOptionsAuthorizationTests
{
    [Fact]
    public void DefaultToolPolicy_DefaultsToAllow()
    {
        var opts = new SentinelOptions();
        Assert.Equal(ToolPolicyDefault.Allow, opts.DefaultToolPolicy);
    }

    [Fact]
    public void RequireToolPolicy_AddsBinding()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only");
        var bindings = opts.GetAuthorizationBindings();
        Assert.Single(bindings);
        Assert.Equal("Bash", bindings[0].Pattern);
        Assert.Equal("admin-only", bindings[0].PolicyName);
    }

    [Fact]
    public void RequireToolPolicy_AllowsMultipleBindings()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only")
            .RequireToolPolicy("delete_*", "admin-only");
        Assert.Equal(2, opts.GetAuthorizationBindings().Count);
    }

    [Fact]
    public void ToolCallAuthorizationException_HasDecision()
    {
        var d = AuthorizationDecision.Deny("admin-only", "missing role");
        var ex = new ToolCallAuthorizationException(d);
        Assert.Same(d, ex.Decision);
        Assert.Contains("admin-only", ex.Message, StringComparison.Ordinal);
    }
}
