using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using AI.Sentinel.Tools;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Authorization.Integration;

/// <summary>
/// A tool the MODEL asks for is run by FunctionInvokingChatClient, so it never appears in the
/// messages the caller sends. These tests pin that authorization still runs before the tool.
/// </summary>
public class ModelInitiatedToolCallTests
{
    public static TheoryData<bool> Orders => new() { true, false };

    private sealed class Harness(int[] ran, IChatClient client, RingBufferAuditStore audit, ChatOptions options)
    {
        public int Ran => ran[0];
        public IChatClient Client => client;
        public RingBufferAuditStore Audit => audit;
        public ChatOptions Options => options;
    }

    // ChatClientBuilder: the FIRST Use is the OUTERMOST client.
    private static Harness Build(bool authorizationOutside, ISecurityContext caller, bool toolsViaAdditionalTools = false, bool modelCallsTool = true)
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var audit = new RingBufferAuditStore();
        var services = new ServiceCollection();
        services.AddSingleton(opts);
        services.AddSingleton<IAuditStore>(audit);
        services.AddSingleton(caller);
        services.AddSingleton<IToolCallGuard>(_ => new DefaultToolCallGuard(
            opts.GetAuthorizationBindings(),
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["admin-only"] = new AdminOnlyPolicy() },
            opts.DefaultToolPolicy, approvalStore: null, logger: null));
        var sp = services.BuildServiceProvider();

        var ran = new int[1];
        var tool = AIFunctionFactory.Create((string id) => { ran[0]++; return "deleted " + id; }, "DeleteUser");

        var builder = new ChatClientBuilder(new ScriptedModel(modelCallsTool));
        Action<FunctionInvokingChatClient> configure = f =>
        {
            if (toolsViaAdditionalTools)
            {
                f.AdditionalTools = [tool];
            }
        };
        var client = (authorizationOutside
            ? builder.UseToolCallAuthorization().UseFunctionInvocation(null, configure)
            : builder.UseFunctionInvocation(null, configure).UseToolCallAuthorization()).Build(sp);
        return new Harness(ran, client, audit, toolsViaAdditionalTools ? new ChatOptions() : new ChatOptions { Tools = [tool] });
    }

    private static Task<ChatResponse> AskAsync(Harness h)
        => h.Client.GetResponseAsync([new ChatMessage(ChatRole.User, "delete 42")], h.Options, TestContext.Current.CancellationToken);

    private static async Task DrainAsync(Harness h)
    {
        await foreach (var _ in h.Client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "delete 42")], h.Options, TestContext.Current.CancellationToken))
        {
        }
    }

    [Fact]
    public async Task AuthorizationOutsideFunctionInvocation_DeniedCall_ToolNeverRunsAndDenialReachesCaller()
    {
        var h = Build(authorizationOutside: true, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        Assert.Equal(0, h.Ran);
    }

    [Fact]
    public async Task AuthorizationInsideFunctionInvocation_DeniedCall_ToolNeverRuns()
    {
        var h = Build(authorizationOutside: false, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        Assert.Equal(0, h.Ran);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_Streaming_ToolNeverRuns(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => DrainAsync(h));

        Assert.Equal(0, h.Ran);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_WritesOneAuthzDenyEntry(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        var entry = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
        Assert.Equal("AUTHZ-DENY", entry.DetectorId);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task AllowedModelCall_ToolRunsOnce(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("alice", "admin"));

        var response = await AskAsync(h);

        Assert.Equal(1, h.Ran);
        Assert.Equal("done", response.Text);
        Assert.Empty(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_ToolFromAdditionalTools_NeverRunsAndIsAuditedOnce(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"), toolsViaAdditionalTools: true);

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        Assert.Equal(0, h.Ran);
        Assert.Equal("AUTHZ-DENY", Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit)).DetectorId);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task AllowedModelCall_ToolFromAdditionalTools_RunsOnce(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("alice", "admin"), toolsViaAdditionalTools: true);

        await AskAsync(h);

        Assert.Equal(1, h.Ran);
    }

    // A denied call that a caller kept in history (call plus its failed result) is history on the next
    // turn: it must not throw again or be audited a second time.
    [Theory]
    [MemberData(nameof(Orders))]
    public async Task AnsweredCallInHistory_IsNotAuthorizedAgain(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"), modelCallsTool: false);
        var history = new List<ChatMessage>
        {
            new(ChatRole.User, "delete 42"),
            new(ChatRole.Assistant, [new FunctionCallContent("c1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })]),
            new(ChatRole.Tool, [new FunctionResultContent("c1", "Error: Function failed.")]),
            new(ChatRole.User, "thanks"),
        };

        var response = await h.Client.GetResponseAsync(history, new ChatOptions(), TestContext.Current.CancellationToken);

        Assert.Equal(0, h.Ran);
        Assert.NotNull(response);
        Assert.Empty(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_Streaming_WritesOneAuthzDenyEntry(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => DrainAsync(h));

        Assert.Equal("AUTHZ-DENY", Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit)).DetectorId);
    }

    [Fact]
    public async Task WrapTools_ReturnsClone_WrapsFunctionsOnce_AndLeavesOtherToolsAlone()
    {
        var fn = AIFunctionFactory.Create(() => "x", "Fn");
        var hosted = new HostedWebSearchTool();
        var original = new ChatOptions { Tools = [fn, hosted] };
        var calls = 0;
        ValueTask<object?> Interceptor(AIFunction inner, AIFunctionArguments args, CancellationToken ct)
        {
            calls++;
            return inner.InvokeAsync(args, ct);
        }

        var once = ToolInvocationInterception.WrapTools(original, Interceptor);
        var twice = ToolInvocationInterception.WrapTools(once, Interceptor);

        Assert.NotSame(original, once);
        Assert.Same(fn, original.Tools![0]);
        Assert.NotSame(fn, once!.Tools![0]);
        Assert.Same(hosted, once.Tools[1]);
        Assert.Same(once.Tools[0], twice!.Tools![0]);
        var result = await ((AIFunction)once.Tools[0]).InvokeAsync(new AIFunctionArguments(StringComparer.Ordinal), TestContext.Current.CancellationToken);
        Assert.Equal("x", result?.ToString(), StringComparer.Ordinal);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void WrapTools_NoTools_ReturnsOptionsUnchanged()
    {
        var options = new ChatOptions();
        Assert.Same(options, ToolInvocationInterception.WrapTools(options, (inner, args, ct) => inner.InvokeAsync(args, ct)));
        Assert.Null(ToolInvocationInterception.WrapTools(null, (inner, args, ct) => inner.InvokeAsync(args, ct)));
    }

    private sealed class ScriptedModel(bool callsTool) : IChatClient
    {
        private int _calls;

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            var reply = callsTool && Interlocked.Increment(ref _calls) == 1
                ? new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })])
                : new ChatMessage(ChatRole.Assistant, "done");
            return Task.FromResult(new ChatResponse(reply));
        }

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var response = await GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
            foreach (var update in response.ToChatResponseUpdates())
            {
                yield return update;
            }
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
