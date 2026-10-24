using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Copilot;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Approvals.Configuration;
using Xunit;
using ZeroAlloc.Authorization;

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
    public async Task PreToolUse_DenyByPolicy_ForwardsTheStoredAuditEntry()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only");
        var guard = new DefaultToolCallGuard(opts.GetAuthorizationBindings(),
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["admin-only"] = new AdminOnlyPolicy() },
            opts.DefaultToolPolicy, approvalStore: null, logger: null);
        var forwarder = new RecordingAuditForwarder();
        var services = new ServiceCollection();
        services.AddAISentinel(o => o.EmbeddingGenerator = new FakeEmbeddingGenerator());
        services.AddSingleton<IAuditForwarder>(forwarder);
        var provider = services.BuildServiceProvider();
        var adapter = CopilotHookAdapter.CreateForTests(provider, new CopilotHookConfig { CallerContextProvider = _ => new TestSecurityContext("bob") }, guard);

        await adapter.HandleAsync(CopilotHookEvent.PreToolUse, new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("{}").RootElement }, TestContext.Current.CancellationToken);

        var denied = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(provider.GetRequiredService<IAuditStore>()),
            e => string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal));
        await forwarder.WaitForAsync(1);
        Assert.Equal(denied, Assert.Single(forwarder.Entries));
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
        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("{}").RootElement };

        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

        Assert.Equal(HookDecision.Block, output.Decision);
        // Phase 3: receipt format is "Authorization denied [<code>] by policy '<name>': <reason>".
        // AdminOnlyPolicy falls back to the default 'policy_denied' code.
        Assert.Contains("Authorization denied [policy_denied]", output.Reason ?? "", StringComparison.Ordinal);
        Assert.Contains("admin-only", output.Reason ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task PreToolUse_DenyByPolicy_SurfacesExplicitPolicyCode()
    {
        // Phase 3 Task 3.2: structured codes (e.g. 'tenant_inactive') propagate verbatim into the
        // operator-facing receipt so log readers can correlate Copilot CLI messages with
        // AuditEntry.PolicyCode rows.
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
        var guard = new ExplicitDenyGuard("TenantActive", "Tenant 'acme' is in evicted state", "tenant_inactive");
        var adapter = CopilotHookAdapter.CreateForTests(provider, new CopilotHookConfig(), guard);

        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("{}").RootElement };
        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Contains("Authorization denied [tenant_inactive]", output.Reason ?? "", StringComparison.Ordinal);
        Assert.Contains("TenantActive", output.Reason ?? "", StringComparison.Ordinal);
        Assert.Contains("Tenant 'acme' is in evicted state", output.Reason ?? "", StringComparison.Ordinal);
    }

    private sealed class ExplicitDenyGuard(string policyName, string reason, string code) : IToolCallGuard
    {
        public ValueTask<AuthorizationDecision> AuthorizeAsync(
            ISecurityContext caller, string toolName, JsonElement args, CancellationToken ct = default) =>
            new(AuthorizationDecision.Deny(policyName, reason, code));
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
        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("""{"command":"ls"}""").RootElement };

        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

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
        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("{}").RootElement };

        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

        Assert.Equal(HookDecision.Block, output.Decision);
    }

    [Fact]
    public async Task PreToolUse_RequireApproval_ReturnsBlockWithReceipt()
    {
        // Same contract as the Claude Code adapter: RequireApprovalDecision must surface the
        // receipt in HookOutput.Reason so the host can show it to the user.
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
        var guard = new RequireApprovalGuard("approval:Bash", "req-xyz", "https://approve.example/req-xyz");
        var adapter = CopilotHookAdapter.CreateForTests(provider, new CopilotHookConfig(), guard);

        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("{}").RootElement };
        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Contains("Approval required to invoke tool 'Bash'", output.Reason ?? "", StringComparison.Ordinal);
        Assert.Contains("Request ID: req-xyz", output.Reason ?? "", StringComparison.Ordinal);
        Assert.Contains("https://approve.example/req-xyz", output.Reason ?? "", StringComparison.Ordinal);
    }

    private sealed class RequireApprovalGuard(string policyName, string requestId, string approvalUrl) : IToolCallGuard
    {
        public ValueTask<AuthorizationDecision> AuthorizeAsync(
            ISecurityContext caller, string toolName, JsonElement args, CancellationToken ct = default) =>
            new(AuthorizationDecision.RequireApproval(
                policyName, requestId, approvalUrl,
                requestedAt: DateTimeOffset.UtcNow, waitTimeout: TimeSpan.FromSeconds(0)));
    }

    private const string BashWhenConfig = """
        {
            "backend": "in-memory",
            "tools": { "Bash": [ { "role": "Ops", "when": { "$.command": "kubectl\\s+delete" } } ] }
        }
        """;

    private static IToolCallGuard BuildBashWhenGuard(out ServiceProvider provider)
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.OnCritical = SentinelAction.Quarantine;
            o.OnHigh = SentinelAction.Quarantine;
            o.OnMedium = SentinelAction.Quarantine;
            o.OnLow = SentinelAction.Quarantine;
            o.EmbeddingGenerator = new FakeEmbeddingGenerator();
            using var doc = JsonDocument.Parse(BashWhenConfig);
            ApprovalBackendSelector.Configure(o, ApprovalConfigLoader.Parse(doc.RootElement));
        });
        provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IToolCallGuard>();
    }

    [Fact]
    public async Task PreToolUse_ArgumentRule_MatchingCommand_BlocksWithApprovalReceipt()
    {
        var guard = BuildBashWhenGuard(out var provider);
        await using var _ = provider;
        var adapter = CopilotHookAdapter.CreateForTests(provider, new CopilotHookConfig(), guard);

        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("""{"command":"kubectl delete ns prod"}""").RootElement };
        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Contains("Approval required to invoke tool 'Bash'", output.Reason ?? "", StringComparison.Ordinal);
        var denied = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(provider.GetRequiredService<IAuditStore>()),
            e => string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal));
        Assert.Contains("policy 'approval:Bash'", denied.Summary, StringComparison.Ordinal);
        Assert.Equal("approval_required", denied.PolicyCode);
    }

    [Fact]
    public async Task PreToolUse_ArgumentRule_NonMatchingCommand_IsAllowed()
    {
        var guard = BuildBashWhenGuard(out var provider);
        await using var _ = provider;
        var adapter = CopilotHookAdapter.CreateForTests(provider, new CopilotHookConfig(), guard);

        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("""{"command":"kubectl get pods"}""").RootElement };
        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

        Assert.NotEqual(HookDecision.Block, output.Decision);
    }

    [Fact]
    public async Task PreToolUse_ArgumentRule_UnparseableStringToolArgs_FailsClosedWithReceipt()
    {
        // toolArgs arrives as a string that is not JSON, so the guard sees a string element
        // and must require approval rather than crash or wave the call through.
        var guard = BuildBashWhenGuard(out var provider);
        await using var _ = provider;
        var adapter = CopilotHookAdapter.CreateForTests(provider, new CopilotHookConfig(), guard);

        var input = new CopilotHookInput { SessionId = "s1", ToolName = "Bash", ToolArgs = JsonDocument.Parse("\"kubectl get pods {not json\"").RootElement };
        var output = await adapter.HandleAsync(CopilotHookEvent.PreToolUse, input, TestContext.Current.CancellationToken);

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Contains("Approval required to invoke tool 'Bash'", output.Reason ?? "", StringComparison.Ordinal);
        var denied = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(provider.GetRequiredService<IAuditStore>()),
            e => string.Equals(e.DetectorId, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, StringComparison.Ordinal));
        Assert.Contains("policy 'approval:Bash'", denied.Summary, StringComparison.Ordinal);
        Assert.Equal("approval_required", denied.PolicyCode);
    }
}
