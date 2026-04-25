using AI.Sentinel.Authorization;
using AI.Sentinel.Mcp.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")]
public class AuthorizationTests
{
    [Fact]
    public void EnvironmentSecurityContext_ReadsEnvVars()
    {
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, "alice");
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, "admin,auditor");
        try
        {
            var ctx = EnvironmentSecurityContext.FromEnvironment();

            Assert.Equal("alice", ctx.Id);
            Assert.Contains("admin", ctx.Roles);
            Assert.Contains("auditor", ctx.Roles);
            Assert.Equal(2, ctx.Roles.Count);
            Assert.Empty(ctx.Claims);
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, null);
            Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, null);
        }
    }

    [Fact]
    public void EnvironmentSecurityContext_NoVars_ReturnsAnonymous()
    {
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, null);
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, null);

        var ctx = EnvironmentSecurityContext.FromEnvironment();

        Assert.Same(AnonymousSecurityContext.Instance, ctx);
    }

    [Fact]
    public void EnvironmentSecurityContext_BlankCallerId_ReturnsAnonymous()
    {
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, "   ");
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, "admin");
        try
        {
            var ctx = EnvironmentSecurityContext.FromEnvironment();

            Assert.Same(AnonymousSecurityContext.Instance, ctx);
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, null);
            Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, null);
        }
    }

    [Fact]
    public void EnvironmentSecurityContext_TrimsAndDropsEmptyRoles()
    {
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, "bob");
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, " admin , , reader ");
        try
        {
            var ctx = EnvironmentSecurityContext.FromEnvironment();

            Assert.Equal("bob", ctx.Id);
            Assert.Equal(2, ctx.Roles.Count);
            Assert.Contains("admin", ctx.Roles);
            Assert.Contains("reader", ctx.Roles);
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, null);
            Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, null);
        }
    }

    [Fact]
    public void EnvironmentSecurityContext_NoRolesVar_ReturnsEmptyRoles()
    {
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, "alice");
        Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerRolesEnvVar, null);
        try
        {
            var ctx = EnvironmentSecurityContext.FromEnvironment();

            Assert.Equal("alice", ctx.Id);
            Assert.Empty(ctx.Roles);
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnvironmentSecurityContext.CallerIdEnvVar, null);
        }
    }
}
