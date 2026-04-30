using AI.Sentinel.Authorization;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Authorization;

public class SecurityContextTests
{
    [Fact]
    public void AnonymousSecurityContext_HasEmptyRolesAndClaims()
    {
        var ctx = AnonymousSecurityContext.Instance;
        Assert.Equal("anonymous", ctx.Id);
        Assert.Empty(ctx.Roles);
        Assert.Empty(ctx.Claims);
    }

    [Fact]
    public void AnonymousSecurityContext_InstanceIsSingleton()
    {
        Assert.Same(AnonymousSecurityContext.Instance, AnonymousSecurityContext.Instance);
    }
}
