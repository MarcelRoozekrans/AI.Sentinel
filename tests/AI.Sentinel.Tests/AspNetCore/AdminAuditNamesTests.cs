using AI.Sentinel.AspNetCore.AdminAudit;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore;

public sealed class AdminAuditNamesTests
{
    [Fact]
    public void Of_RefusesAnActionThatIsNotDefined() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => AdminAuditNames.Of((AdminAuditAction)999));

    [Fact]
    public void Of_RefusesAChannelThatIsNotDefined() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => AdminAuditNames.Of((AdminAuditChannel)999));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Approve")]
    public void IsKnown_RejectsUnknownNames(string? name)
    {
        Assert.False(AdminAuditNames.IsKnownAction(name));
        Assert.False(AdminAuditNames.IsKnownChannel(name));
    }
}
