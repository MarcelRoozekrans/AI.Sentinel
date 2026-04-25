using System.Text.Json;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization.Policies;

public class NoSystemPathsPolicyTests
{
    [Fact]
    public void Bash_WithSystemPath_Denies()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice", "admin"),
            "Bash", JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement);
        Assert.False(p.IsAuthorized(ctx));
    }

    [Fact]
    public void Bash_WithSafePath_Allows()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice"),
            "Bash", JsonDocument.Parse("""{"path":"/tmp/foo"}""").RootElement);
        Assert.True(p.IsAuthorized(ctx));
    }

    [Fact]
    public void OtherTool_AlwaysAllowed()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice"),
            "Read", JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement);
        Assert.True(p.IsAuthorized(ctx));
    }
}
