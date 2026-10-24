using System.Reflection;
using AI.Sentinel.Approvals;
using Xunit;

namespace AI.Sentinel.Tests.Approvals;

public class ApprovalSpecTests
{
    [Fact]
    public void WithPolicyName_CopiesEveryProperty_AndLeavesOriginalUnchanged()
    {
        var spec = new ApprovalSpec
        {
            PolicyName = "approval:Bash",
            GrantDuration = TimeSpan.FromMinutes(42),
            RequireJustification = false,
            WaitTimeout = TimeSpan.FromSeconds(7),
            BackendBinding = "role",
            GrantScope = ApprovalGrantScope.Call,
        };

        var copy = spec.WithPolicyName("approval:Bash#0123456789abcdef0123456789abcdef");

        Assert.NotSame(spec, copy);
        Assert.Equal("approval:Bash#0123456789abcdef0123456789abcdef", copy.PolicyName);
        Assert.Equal("approval:Bash", spec.PolicyName);

        // Every public settable property other than PolicyName must be copied. The name list
        // fails the test when a property is added, so WithPolicyName gets updated with it.
        var properties = typeof(ApprovalSpec)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanWrite && !string.Equals(p.Name, nameof(ApprovalSpec.PolicyName), StringComparison.Ordinal))
            .ToList();
        Assert.Equal(
            ["BackendBinding", "GrantDuration", "GrantScope", "RequireJustification", "WaitTimeout"],
            properties.Select(p => p.Name).Order(StringComparer.Ordinal),
            StringComparer.Ordinal);
        foreach (var property in properties)
            Assert.Equal(property.GetValue(spec), property.GetValue(copy));
    }
}
