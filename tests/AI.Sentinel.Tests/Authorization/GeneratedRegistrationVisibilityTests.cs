using System.Reflection;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class GeneratedRegistrationVisibilityTests
{
    // Issues 493 and 512: every project referencing AI.Sentinel gets the ZeroAlloc.Authorization
    // generator transitively. A public generated registration in a shipped assembly collides (CS0121)
    // with the one generated in any app that declares its own policies.
    public static TheoryData<string> ShippedAssemblies => new()
    {
        typeof(SentinelPipeline).Assembly.GetName().Name!,
        typeof(AI.Sentinel.AspNetCore.ApplicationBuilderExtensions).Assembly.GetName().Name!,
        typeof(AI.Sentinel.ClaudeCode.HookInput).Assembly.GetName().Name!,
        typeof(AI.Sentinel.Copilot.CopilotHookInput).Assembly.GetName().Name!,
        typeof(AI.Sentinel.Mcp.Authorization.EnvironmentSecurityContext).Assembly.GetName().Name!,
    };

    [Theory]
    [MemberData(nameof(ShippedAssemblies))]
    public void GeneratedAuthorizationRegistration_IsNotPublic(string assemblyName)
    {
        var assembly = Assembly.Load(assemblyName);

        Assert.DoesNotContain(
            assembly.GetExportedTypes(),
            t => string.Equals(t.FullName, "ZeroAlloc.Authorization.Generated.GeneratedAuthorizationRegistration", StringComparison.Ordinal));
    }
}
