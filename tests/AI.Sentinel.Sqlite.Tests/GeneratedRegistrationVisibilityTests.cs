using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

public class GeneratedRegistrationVisibilityTests
{
    // Issue 512: this package gets the ZeroAlloc.Authorization generator through AI.Sentinel. A public
    // generated registration collides (CS0121) with the one generated in an app that declares its own policies.
    [Fact]
    public void GeneratedAuthorizationRegistration_IsNotPublic()
    {
        var assembly = typeof(AI.Sentinel.Sqlite.SqliteAuditStoreOptions).Assembly;

        Assert.DoesNotContain(
            assembly.GetExportedTypes(),
            t => string.Equals(t.FullName, "ZeroAlloc.Authorization.Generated.GeneratedAuthorizationRegistration", StringComparison.Ordinal));
    }
}
