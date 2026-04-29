using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Copilot;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Copilot;

public class AuthorizationTests
{
    private static CopilotHookAdapter BuildAdapter(SentinelOptions opts, CopilotHookConfig config)
    {
        var policiesByName = new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal)
        {
            ["admin-only"] = new AdminOnlyPolicy(),
        };
        var guard = new DefaultToolCallGuard(opts.GetAuthorizationBindings(), policiesByName, opts.DefaultToolPolicy, approvalStore: null, logger: null);

        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.OnCritical = SentinelAction.Quarantine;
            o.OnHigh = SentinelAction.Quarantine;
            o.OnMedium = SentinelAction.Quarantine;
            o.OnLow = SentinelAction.Quarantine;
            o.EmbeddingGenerator = new FakeEmbeddingGenerator();
        });
        var provider = services.BuildServiceProvider();
        return CopilotHookAdapter.CreateForTests(provider, config, guard);
    }

    [Fact]
    public async Task PreToolUse_DenyByPolicy_ReturnsBlock()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only");
        var config = new CopilotHookConfig
        {
            CallerContextProvider = _ => new TestSecurityContext("bob"),
        };
        var adapter = BuildAdapter(opts, config);
        var input = new CopilotHookInput("s1", null, "Bash", JsonDocument.Parse("{}").RootElement, null);

        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, default);

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Contains("admin-only", output.Reason ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task PreToolUse_AllowByPolicy_FallsThroughToDetection()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only");
        var config = new CopilotHookConfig
        {
            CallerContextProvider = _ => new TestSecurityContext("alice", "admin"),
        };
        var adapter = BuildAdapter(opts, config);
        var input = new CopilotHookInput("s1", null, "Bash", JsonDocument.Parse("""{"command":"ls"}""").RootElement, null);

        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, default);

        // Authorization passed; detection may still report Allow/Warn for a benign payload,
        // but must not Block on the authz path.
        Assert.NotEqual(HookDecision.Block, output.Decision);
    }

    [Fact]
    public async Task PreToolUse_NoCallerContextProvider_AnonymousDeniesPolicy()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only");
        var config = new CopilotHookConfig(); // no provider -> AnonymousSecurityContext
        var adapter = BuildAdapter(opts, config);
        var input = new CopilotHookInput("s1", null, "Bash", JsonDocument.Parse("{}").RootElement, null);

        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, default);

        Assert.Equal(HookDecision.Block, output.Decision);
    }
}
