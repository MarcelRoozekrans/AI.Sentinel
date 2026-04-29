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
}
