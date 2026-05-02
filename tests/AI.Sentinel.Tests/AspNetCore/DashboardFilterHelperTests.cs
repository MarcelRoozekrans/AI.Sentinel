using AI.Sentinel.AspNetCore;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardFilterHelperTests
{
    [Theory]
    [InlineData("SEC-01",       "security",      true)]
    [InlineData("SEC-21",       "security",      true)]
    [InlineData("HAL-08",       "security",      false)]
    [InlineData("HAL-08",       "hallucination", true)]
    [InlineData("OPS-12",       "operational",   true)]
    [InlineData("AUTHZ-DENY",   "authorization", true)]
    [InlineData("SEC-01",       "authorization", false)]
    public void IsInCategory_PrefixMatch_KnownCategories(string detectorId, string category, bool expected)
    {
        Assert.Equal(expected, DashboardHandlers.IsInCategory(detectorId, category));
    }

    [Theory]
    [InlineData("SEC-01", "")]
    [InlineData("HAL-08", null)]
    [InlineData("OPS-12", "unknown_category")]
    public void IsInCategory_NullEmptyOrUnknown_ReturnsTrue(string detectorId, string? category)
    {
        Assert.True(DashboardHandlers.IsInCategory(detectorId, category));
    }
}
