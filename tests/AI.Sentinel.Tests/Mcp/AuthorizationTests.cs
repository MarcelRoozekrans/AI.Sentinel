using System.Runtime.CompilerServices;
using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp;
using AI.Sentinel.Mcp.Authorization;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
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

    [Fact]
    public async Task ToolsCall_DenyByPolicy_ThrowsMcpProtocolException()
    {
        var guard = new StubGuard(allow: false, policyName: "BashDenyPolicy", reason: "Bash is forbidden");
        var pipeline = McpPipelineFactory.Create(DefaultHookConfig(), McpDetectorPreset.Security);
        using var stderr = new StringWriter();
        var nextInvoked = false;

        var filter = ToolCallInterceptor.Create(
            pipeline,
            maxScanBytes: 64 * 1024,
            stderr: stderr,
            guard: guard);

        ValueTask<CallToolResult> Next(RequestContext<CallToolRequestParams> _, CancellationToken __)
        {
            nextInvoked = true;
            return new ValueTask<CallToolResult>(new CallToolResult());
        }

        var handler = filter(Next);
        var ctx = BuildRequestContext(new CallToolRequestParams { Name = "Bash" });

        var ex = await Assert.ThrowsAsync<McpProtocolException>(
            async () => await handler(ctx, CancellationToken.None));

        Assert.Equal(McpErrorCode.InvalidRequest, ex.ErrorCode);
        Assert.Contains("BashDenyPolicy", ex.Message, StringComparison.Ordinal);
        Assert.False(nextInvoked);
    }

    [Fact]
    public async Task ToolsCall_AllowByPolicy_PassesThroughToTarget()
    {
        var guard = new StubGuard(allow: true);
        var pipeline = McpPipelineFactory.Create(DefaultHookConfig(), McpDetectorPreset.Security);
        using var stderr = new StringWriter();
        var nextInvoked = false;
        var expected = new CallToolResult
        {
            Content = [new TextContentBlock { Text = "ok" }],
        };

        var filter = ToolCallInterceptor.Create(
            pipeline,
            maxScanBytes: 64 * 1024,
            stderr: stderr,
            guard: guard);

        ValueTask<CallToolResult> Next(RequestContext<CallToolRequestParams> _, CancellationToken __)
        {
            nextInvoked = true;
            return new ValueTask<CallToolResult>(expected);
        }

        var handler = filter(Next);
        var ctx = BuildRequestContext(new CallToolRequestParams { Name = "read_file" });

        var result = await handler(ctx, CancellationToken.None);

        Assert.True(nextInvoked);
        Assert.Same(expected, result);
    }

    private static HookConfig DefaultHookConfig() => new(
        OnCritical: HookDecision.Block,
        OnHigh:     HookDecision.Block,
        OnMedium:   HookDecision.Block,
        OnLow:      HookDecision.Block,
        Verbose:    false);

    // RequestContext<T> requires a non-null McpServer, but the interceptor only reads ctx.Params.
    // Use RuntimeHelpers.GetUninitializedObject to bypass the validating constructor.
    private static RequestContext<CallToolRequestParams> BuildRequestContext(CallToolRequestParams parameters)
    {
        var ctx = (RequestContext<CallToolRequestParams>)RuntimeHelpers.GetUninitializedObject(
            typeof(RequestContext<CallToolRequestParams>));
        ctx.Params = parameters;
        return ctx;
    }

    private sealed class StubGuard(bool allow, string? policyName = null, string? reason = null) : IToolCallGuard
    {
        public ValueTask<AuthorizationDecision> AuthorizeAsync(
            ISecurityContext caller,
            string toolName,
            JsonElement args,
            CancellationToken ct = default) =>
            new(allow
                ? AuthorizationDecision.Allow
                : AuthorizationDecision.Deny(policyName ?? "stub", reason ?? "denied"));
    }
}
