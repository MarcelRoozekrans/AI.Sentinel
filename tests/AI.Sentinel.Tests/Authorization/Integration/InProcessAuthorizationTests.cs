using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Authorization.Integration;

public class InProcessAuthorizationTests
{
    private static IChatClient BuildPipeline(SentinelOptions opts, ISecurityContext caller, IChatClient inner)
    {
        var services = new ServiceCollection();
        services.AddSingleton(opts);
        services.AddSingleton<IAuthorizationPolicy, AdminOnlyPolicy>();
        services.AddSingleton(caller);
        services.AddSingleton<IToolCallGuard>(sp =>
        {
            var policiesByName = new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal);
            foreach (var p in sp.GetServices<IAuthorizationPolicy>())
            {
                var attrs = p.GetType().GetCustomAttributes(typeof(AuthorizationPolicyAttribute), false);
                if (attrs.Length == 0) continue;
                var name = ((AuthorizationPolicyAttribute)attrs[0]).Name;
                policiesByName[name] = p;
            }
            return new DefaultToolCallGuard(opts.GetAuthorizationBindings(), policiesByName, opts.DefaultToolPolicy, approvalStore: null, logger: null);
        });
        var sp = services.BuildServiceProvider();

        return new ChatClientBuilder(inner)
            .UseToolCallAuthorization()
            .Build(sp);
    }

    [Fact]
    public async Task BoundTool_AdminCaller_Allowed()
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("alice", "admin"), inner);

        var fnCall = new FunctionCallContent("call-1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" });
        var resp = await client.GetResponseAsync([new ChatMessage(ChatRole.Assistant, [fnCall])]);
        Assert.NotNull(resp);
    }

    [Fact]
    public async Task BoundTool_NonAdminCaller_Throws()
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("bob"), inner);

        var fnCall = new FunctionCallContent("call-1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" });
        var ex = await Assert.ThrowsAsync<ToolCallAuthorizationException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.Assistant, [fnCall])]));
        Assert.NotNull(ex.Decision);
        Assert.Equal("admin-only", Assert.IsType<AuthorizationDecision.DenyDecision>(ex.Decision!).PolicyName);
    }

    [Fact]
    public async Task UnboundTool_AllowedByDefault()
    {
        var opts = new SentinelOptions(); // no bindings
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("bob"), inner);

        var fnCall = new FunctionCallContent("call-1", "Read", new Dictionary<string, object?>(StringComparer.Ordinal) { ["path"] = "/tmp" });
        var resp = await client.GetResponseAsync([new ChatMessage(ChatRole.Assistant, [fnCall])]);
        Assert.NotNull(resp);
    }

    [Fact]
    public async Task NoFunctionCall_PassesThrough()
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("bob"), inner);

        var resp = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);
        Assert.NotNull(resp);
    }

    private sealed class EchoChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
