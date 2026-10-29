using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class GeneratedRegistrationVisibilityTests
{
    // Issue 493: a public generated registration in AI.Sentinel.dll collides (CS0121)
    // with the one generated in any app that declares its own policies.
    [Fact]
    public void GeneratedAuthorizationRegistration_IsNotPublic()
    {
        var assembly = typeof(SentinelPipeline).Assembly;

        Assert.DoesNotContain(
            assembly.GetExportedTypes(),
            t => string.Equals(t.FullName, "ZeroAlloc.Authorization.Generated.GeneratedAuthorizationRegistration", StringComparison.Ordinal));
    }
}
