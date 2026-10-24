using System.Linq;
using AI.Sentinel;
using AI.Sentinel.Approvals;
using Xunit;

namespace AI.Sentinel.Tests.Approvals;

public class SentinelOptionsApprovalExtensionsTests
{
    [Fact]
    public void RequireApproval_AddsBindingWithSpec()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("delete_database", spec =>
        {
            spec.PolicyName = "AdminApproval";
            spec.GrantDuration = TimeSpan.FromMinutes(30);
            spec.BackendBinding = "Database Administrator";
        });

        var binding = opts.GetAuthorizationBindings().Single(b => string.Equals(b.Pattern, "delete_database", StringComparison.Ordinal));
        Assert.NotNull(binding.ApprovalSpec);
        Assert.Equal("AdminApproval", binding.ApprovalSpec!.PolicyName);
        Assert.Equal("Database Administrator", binding.ApprovalSpec.BackendBinding);
        Assert.Equal(TimeSpan.FromMinutes(30), binding.ApprovalSpec.GrantDuration);
    }

    [Fact]
    public void RequireApproval_DefaultGrantDurationIs15Minutes()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("send_payment", spec => spec.PolicyName = "FinanceApproval");

        var binding = opts.GetAuthorizationBindings().Single(b => string.Equals(b.Pattern, "send_payment", StringComparison.Ordinal));
        Assert.Equal(TimeSpan.FromMinutes(15), binding.ApprovalSpec!.GrantDuration);
    }

    [Fact]
    public void RequireApproval_FluentChain_ReturnsSameOptions()
    {
        var opts = new SentinelOptions();
        var result = opts.RequireApproval("x", spec => spec.PolicyName = "p");
        Assert.Same(opts, result);
    }

    [Fact]
    public void WhenArgument_AddsConditionsInOrder()
    {
        var spec = new ApprovalSpec { PolicyName = "p" };
        var result = spec.WhenArgument("$.command", "^rm").WhenArgument("$.cwd", "prod");

        Assert.Same(spec, result);
        Assert.Equal(2, spec.Conditions.Count);
        Assert.Equal("$.command", spec.Conditions[0].Path.Text);
        Assert.Equal("^rm", spec.Conditions[0].Pattern);
        Assert.Equal("$.cwd", spec.Conditions[1].Path.Text);
        Assert.Equal("prod", spec.Conditions[1].Pattern);
    }

    [Fact]
    public void WhenArgument_BadPath_Throws()
    {
        var spec = new ApprovalSpec { PolicyName = "p" };
        var ex = Assert.ThrowsAny<ArgumentException>(() => spec.WhenArgument("command[", "x"));
        Assert.Contains("command[", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WhenArgument_BadRegex_Throws()
    {
        var spec = new ApprovalSpec { PolicyName = "p" };
        var ex = Assert.ThrowsAny<ArgumentException>(() => spec.WhenArgument("$.command", "("));
        Assert.Contains("(", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RequireApproval_SamePatternTwice_NumbersLaterEntries()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("Bash", _ => { });
        opts.RequireApproval("Bash", _ => { });
        opts.RequireApproval("Bash", _ => { });

        var names = opts.GetAuthorizationBindings().Select(b => b.ApprovalSpec!.PolicyName).ToArray();
        Assert.Equal(new[] { "approval:Bash", "approval:Bash[1]", "approval:Bash[2]" }, names);
    }

    [Fact]
    public void RequireApproval_ExplicitName_IsKept()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("Bash", _ => { });
        opts.RequireApproval("Bash", spec => spec.PolicyName = "kubectl-delete");

        var names = opts.GetAuthorizationBindings().Select(b => b.ApprovalSpec!.PolicyName).ToArray();
        Assert.Equal(new[] { "approval:Bash", "kubectl-delete" }, names);
    }

    [Fact]
    public void RequireApproval_DuplicateName_Throws()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("A", spec => spec.PolicyName = "x");
        var ex = Assert.Throws<InvalidOperationException>(
            () => opts.RequireApproval("B", spec => spec.PolicyName = "x"));
        Assert.Contains("x", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GrantScope_DefaultsToRule()
    {
        Assert.Equal(ApprovalGrantScope.Rule, new ApprovalSpec { PolicyName = "p" }.GrantScope);
    }

    [Fact]
    public void RequireApproval_ExplicitNameBetween_StillCountsForIndex()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("Bash", _ => { });
        opts.RequireApproval("Bash", spec => spec.PolicyName = "kubectl-delete");
        opts.RequireApproval("Bash", _ => { });

        var names = opts.GetAuthorizationBindings().Select(b => b.ApprovalSpec!.PolicyName).ToArray();
        Assert.Equal(new[] { "approval:Bash", "kubectl-delete", "approval:Bash[2]" }, names);
    }

    [Fact]
    public void RequireApproval_DefaultNameCollidesWithExplicitName_Throws()
    {
        var opts = new SentinelOptions();
        opts.RequireApproval("Other", spec => spec.PolicyName = "approval:Bash[1]");
        opts.RequireApproval("Bash", _ => { });
        var ex = Assert.Throws<InvalidOperationException>(() => opts.RequireApproval("Bash", _ => { }));
        Assert.Contains("approval:Bash[1]", ex.Message, StringComparison.Ordinal);
    }
}
