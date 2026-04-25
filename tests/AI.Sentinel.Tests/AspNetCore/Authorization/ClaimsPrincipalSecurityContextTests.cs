using System.Security.Claims;
using AI.Sentinel.AspNetCore.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore.Authorization;

public class ClaimsPrincipalSecurityContextTests
{
    [Fact]
    public void RoleClaims_ExposedAsRoles()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "alice"),
            new Claim(ClaimTypes.Role, "admin"),
            new Claim(ClaimTypes.Role, "auditor"),
        ], authenticationType: "Test"));

        var ctx = new ClaimsPrincipalSecurityContext(principal);
        Assert.Equal("alice", ctx.Id);
        Assert.Contains("admin", ctx.Roles);
        Assert.Contains("auditor", ctx.Roles);
        Assert.Equal(2, ctx.Roles.Count);
    }

    [Fact]
    public void NonRoleClaims_ExposedAsClaims()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "alice"),
            new Claim("tenant", "acme"),
            new Claim("scope", "tools:execute"),
        ], "Test"));

        var ctx = new ClaimsPrincipalSecurityContext(principal);
        Assert.Equal("acme", ctx.Claims["tenant"]);
        Assert.Equal("tools:execute", ctx.Claims["scope"]);
        Assert.False(ctx.Claims.ContainsKey(ClaimTypes.NameIdentifier)); // Id is exposed via Id property, not Claims
    }

    [Fact]
    public void NoNameIdentifier_FallsBackToAnonymous()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var ctx = new ClaimsPrincipalSecurityContext(principal);
        Assert.Equal("anonymous", ctx.Id);
    }
}
