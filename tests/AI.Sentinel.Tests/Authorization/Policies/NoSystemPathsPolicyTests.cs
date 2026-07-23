using System.Text.Json;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization.Policies;

public class NoSystemPathsPolicyTests
{
    [Fact]
    public async Task Bash_WithSystemPath_Denies()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice", "admin"),
            "Bash", JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement);
        Assert.True((await p.EvaluateAsync(ctx)).IsFailure);
    }

    [Fact]
    public async Task Bash_WithSafePath_Allows()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice"),
            "Bash", JsonDocument.Parse("""{"path":"/tmp/foo"}""").RootElement);
        Assert.True((await p.EvaluateAsync(ctx)).IsSuccess);
    }

    [Fact]
    public async Task OtherTool_AlwaysAllowed()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice"),
            "Read", JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement);
        Assert.True((await p.EvaluateAsync(ctx)).IsSuccess);
    }
}
